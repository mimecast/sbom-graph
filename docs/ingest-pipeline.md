# Asynchronous SBOM ingest pipeline

This guide documents the asynchronous SBOM ingest pipeline introduced to
eliminate the liveness-probe-timeout crash pattern described in
[`sbom-graph-api-troubleshooting.md` §10](./sbom-graph-api-troubleshooting.md#10-ingest-induced-liveness-probe-timeouts).

It is the **authoritative reference** for the topology, configuration,
HTTP contract, and operational behaviour of the pipeline. Make changes to
the queue topology, worker concurrency, or the `?sync=true` escape hatch
only after reading this file end-to-end.

Audience: cluster operators, API/CLI maintainers, and anyone integrating
against the SBOM ingest endpoints (CI pipelines, the
`sonatype-lifecycle-release-listener`, the `sbom-graph-cli`, third-party
scanners).

Tested namespace in examples: `sbom-graph`. Substitute your own if different.

---

## Table of contents

1. [Why an async pipeline](#1-why-an-async-pipeline)
2. [Topology](#2-topology)
3. [HTTP contract](#3-http-contract)
4. [Client-side conventions](#4-client-side-conventions)
5. [Configuration reference](#5-configuration-reference)
6. [Operational checks](#6-operational-checks)
7. [Threat model summary](#7-threat-model-summary)
8. [Migration notes](#8-migration-notes)
9. [Troubleshooting cross-reference](#9-troubleshooting-cross-reference)

---

## 1. Why an async pipeline

A typical `POST /ingest/cyclonedx` request used to spend tens of seconds
on the Flask request thread:

1. Parse the CycloneDX JSON into Python dicts (CPU-bound, GIL-held).
2. Walk the parse tree and issue dozens-to-thousands of `GRAPH.QUERY`
   writes over mTLS to FalkorDB. With `THREAD_COUNT=1` (the
   persistence-stability mitigation in
   [`falkordb-backup-and-restore.md` §5](./falkordb-backup-and-restore.md#5-diagnose-and-recover-a-stuck-snapshot))
   those writes are serialised database-side.

While that work runs the request thread holds one of the four
`gthread` slots Gunicorn has per pod. Concurrent ingests saturate the
pool, the static `GET /health` probe queues longer than its
`timeoutSeconds`, the kubelet records consecutive failures, and after
`failureThreshold` SIGKILLs the container. The pod was *healthy* — it
was just too busy to answer trivia.

Pushing the heavy work onto a dedicated Celery worker pool, behind a
queue that **never** runs anything other than ingest, structurally
eliminates the failure class:

- The Flask request thread does only validation + `LPUSH` (single Redis
  command, sub-millisecond) before returning `202 Accepted`.
- The four `gthread` slots stay free for `/health`, reports, and other
  read traffic.
- The CPU and memory cost of parse-and-persist is paid in the worker
  container, which has its own resource limits and is not subject to
  kubelet liveness probes against Flask.

The legacy synchronous code path is preserved verbatim behind a
`?sync=true` query flag (see [§3.4](#34-the-synctrue-escape-hatch)) so
callers that genuinely need to block on completion (small SBOMs,
debugging, tests) keep working.

---

## 2. Topology

```
                             ┌──────────────────────────────┐
                             │   sbom-graph-api (Flask)     │
 POST /ingest/cyclonedx  ──▶ │  validate + Celery send_task │
 POST /ingest/spdx       ──▶ │   (returns 202 in ms)        │
 POST /ingest/sbom       ──▶ │                              │
 POST /ingest/vex        ──▶ │                              │
                             └──────┬───────────────────────┘
                                    │ Celery broker (Redis DB 1)
                                    │ queue=ingest, prefetch=1
                                    ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  enrichment-ingest-worker  (Deployment)                          │
 │  concurrency: 2, replicas: 1                                     │
 │  consumes ONLY queue=ingest                                      │
 │  runs sbom_graph_enrichment.ingest_tasks.ingest_*                │
 └──────┬──────────────────────────────────────────────────────────┘
        │   GRAPH.QUERY (mTLS)
        ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  FalkorDB (graph store)                                          │
 └─────────────────────────────────────────────────────────────────┘

                                    ▲
                                    │ Celery result backend (Redis DB 2)
                                    │ AsyncResult.state, .result
                                    │
 GET /ingest/jobs/<id>   ◀──── sbom-graph-api (Flask)
                                    ▲
                                    │ polls every poll_interval
                                    │
 sbom-graph-cli  ──────────────────┘
```

Three pools talk to FalkorDB. They never share work:

| Pool | Deployment | Listens on queue(s) | Purpose |
|---|---|---|---|
| **`sbom-graph-api`** | `sbom-graph-sbom-graph-api` | n/a (HTTP only) | Flask: report, visualization, ingest API. |
| **`enrichment-worker`** | `sbom-graph-enrichment-worker` | `enrichment`, `celery` (default) | Long-running enrichment scans (OSV, ClearlyDefined, OpenSSF Scorecard, Sonatype OSS Index, deps.dev, trust score computation). |
| **`enrichment-ingest-worker`** | `sbom-graph-enrichment-ingest-worker` | `ingest` *only* | SBOM parse-and-persist for `POST /ingest/*`. |

The **priority guarantee** the dedicated pool delivers is structural:
an SBOM upload triggered by `POST /ingest/cyclonedx` will never wait
behind an in-flight `enrich_all_packages` run that's already occupying
every slot in the main enrichment pool. Conversely, an SBOM ingest
cannot starve the enrichment pool — they live on different queues
with different workers.

### 2.1 Why `--prefetch-multiplier=1`

A Celery worker default-prefetches `4 × concurrency` tasks from the
broker into local memory. For ingest that's catastrophic: each task
carries a full SBOM document (up to 50 MB JSON, an order of magnitude
larger after Python-object decode), so a prefetch buffer would balloon
the worker RSS well past its 1 GiB limit and OOMKill the container.

`--prefetch-multiplier=1` forces the worker to fetch exactly one task
at a time per slot. The trade-off is a tiny per-task RTT to the
broker, which is irrelevant relative to the multi-second parse cost.

### 2.2 Why `concurrency: 2`

Two slots per worker pod (so `2 replicas × 2 = 4` simultaneous ingest
jobs at full scale-out) is the resident-memory-driven ceiling on a
1 GiB-limit worker: each in-flight task holds the parsed Python
object graph for its SBOM plus FalkorDB driver buffers. Going to 4
per pod risks OOM on the larger SBOMs in production. Going below 2
serialises ingest unnecessarily on the typical workload. Raise this
in `values.yaml → enrichment.ingest.concurrency` only after measuring
peak RSS under load and raising `resources.limits.memory` in step.

---

## 3. HTTP contract

### 3.1 Endpoints

All four ingest endpoints share the same async-by-default contract:

| Endpoint | Body |
|---|---|
| `POST /ingest/cyclonedx` | `{"sbom": <CycloneDX 1.4/1.5 JSON>, "app_id"?, "public_app_id"?, "project_url"?}` |
| `POST /ingest/spdx`      | `{"sbom": <SPDX 2.3 JSON>, "app_id"?, "public_app_id"?, "project_url"?}` |
| `POST /ingest/sbom`      | Same body, format auto-detected (`bomFormat`/`metadata.component` ⇒ CycloneDX, `spdxVersion` ⇒ SPDX). |
| `POST /ingest/vex`       | OpenVEX JSON document. |

Plus the new job-status endpoint:

| Endpoint | Description |
|---|---|
| `GET /ingest/jobs/<job_id>` | Return the current state of an async ingest job. |

All require `Authorization: Bearer <token>` when `AUTH_ENABLED=true`.

### 3.2 Async-default response (`202 Accepted`)

```http
HTTP/1.1 202 Accepted
Content-Type: application/json
Location: /ingest/jobs/8a73…d1
```

```json
{
  "status": "accepted",
  "record_id": "a9c2…42",
  "job_id": "8a73…d1",
  "status_url": "/ingest/jobs/8a73…d1",
  "format": "cyclonedx"
}
```

The `record_id` is the deterministic SBOM record id; it's allocated
server-side at validation time and is identical to what the worker
will eventually persist. Clients can use it immediately as a
provenance handle in audit logs without waiting for completion.

The `job_id` is a Celery task id (UUID). It's only meaningful when
combined with the `status_url`.

### 3.3 Job status (`GET /ingest/jobs/<job_id>`)

`<job_id>` must be a valid UUID — any other shape returns `400`.

Non-terminal:

```json
{ "job_id": "8a73…d1", "state": "STARTED", "terminal": false }
```

Terminal SUCCESS:

```json
{
  "job_id": "8a73…d1",
  "state": "SUCCESS",
  "terminal": true,
  "result": {
    "status": "ok",
    "record_id": "a9c2…42",
    "format": "cyclonedx",
    "projects_count": 1,
    "dependencies_count": 247,
    "defects_count": 19
  }
}
```

The `result` dict is byte-for-byte the same shape the legacy
synchronous path returned in its `201` body. This is what makes the
CLI's transparent-polling behaviour work without legacy scripts
noticing.

Terminal FAILURE:

```json
{
  "job_id": "8a73…d1",
  "state": "FAILURE",
  "terminal": true,
  "result": {
    "status": "error",
    "error": "Ingest job failed; see server logs"
  }
}
```

The worker tasks catch their own validation exceptions and return a
sanitised `{"status": "error", "error": "<message>"}` dict from a
SUCCESS state — that's the recommended path. An actual Celery
`FAILURE` state means an uncaught exception or worker crash; in that
case the API endpoint returns the same sanitised generic message
**and** logs the raw event at WARNING level (the raw exception is
never sent to the client; CWE-209).

Other states:

| State | Meaning | `terminal` |
|---|---|---|
| `PENDING` | Celery hasn't seen the task yet, *or* the task id is unknown to the result backend (Celery limitation). | `false` |
| `RECEIVED` | A worker has pulled the task off the queue but not started it. | `false` |
| `STARTED` | A worker is currently processing the task. | `false` |
| `SUCCESS` | Task completed; `result` carries the summary. | `true` |
| `FAILURE` | Uncaught exception; see above. | `true` |
| `REVOKED` | Task was revoked before it ran. | `true` |

### 3.4 The `?sync=true` escape hatch

`POST /ingest/<endpoint>?sync=true` (or `?sync=1`, `?sync=yes`) runs
the same `process_*` helpers inline on the Flask request thread and
returns the legacy `201 Created`:

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

```json
{
  "status": "ok",
  "record_id": "a9c2…42",
  "format": "cyclonedx",
  "projects_count": 1,
  "dependencies_count": 247,
  "defects_count": 19
}
```

Use it for:

- Very small SBOMs in test scripts where the round-trip cost of
  enqueue + poll is comparable to the parse itself.
- Debug sessions where you want a synchronous traceback.
- Environments that intentionally disable the dedicated ingest pool
  (`enrichment.ingest.enabled: false`) — in that case the default
  path returns `503 Ingest pipeline not available` and `?sync=true`
  is the only way to ingest.

Do **not** use it from CI/CD pipelines that submit medium-or-larger
SBOMs against a production cluster: that's exactly the workload the
async path exists to handle, and forcing it through `?sync=true` will
re-introduce the §10 liveness-probe crash pattern.

### 3.5 Error responses (all paths)

| Status | When |
|---|---|
| `400` | Body is missing, not JSON, fails schema validation, or `/ingest/jobs/<id>` got a non-UUID id. |
| `413` | Body exceeds `MAX_SBOM_SIZE` (50 MB by default). |
| `415` | `Content-Type` is not `application/json`. |
| `422` | (sync path only) CycloneDX/SPDX structural validation failed inside the parser. |
| `500` | (sync path only) Unexpected processing error. The async path never returns 500; processing errors surface via `GET /ingest/jobs/<id>` with `state: SUCCESS` and `result.status: error`. |
| `503` | Async path: enrichment pipeline (Celery) not installed in this image. |

---

## 4. Client-side conventions

### 4.1 `sbom-graph-cli`

The CLI defaults to `--wait`, which polls `GET /ingest/jobs/<id>`
behind a Rich spinner until terminal. From the user's perspective
this preserves the historical "submit and get a summary back" UX with
no flag changes.

```bash
# Default: submit + poll + render summary (legacy UX)
sbom-graph push-sbom path/to/sbom.json

# Fire-and-forget: print the 202 envelope and exit immediately
sbom-graph push-sbom --no-wait path/to/sbom.json

# Legacy synchronous server path (forces ?sync=true)
sbom-graph push-sbom --sync path/to/sbom.json

# Tune the polling loop (defaults: --poll-interval 1.0, --poll-timeout 600)
sbom-graph push-sbom --poll-interval 0.5 --poll-timeout 1800 path/to/sbom.json
```

A polling timeout produces an `APIError(status_code=504)` so CI exit
codes still surface the failure; a worker-reported FAILURE produces
an `APIError(status_code=500)` with the sanitised error message.

The CLI client also exposes the underlying primitives:

```python
from sbom_graph_cli.client import SBOMGraphClient

client = SBOMGraphClient("https://sbom-graph-api…", token="…")

# Submit and return the raw 202 envelope:
envelope = client.ingest_sbom("sbom.json", wait=False)
print(envelope["job_id"], envelope["status_url"])

# Poll explicitly:
status = client.get_ingest_job_status(envelope["job_id"])
```

### 4.2 HTTP-direct clients (Sonatype listener, ad-hoc curl)

A robust poller follows three rules:

1. Start with `poll_interval ≥ 1 s`. Anything tighter risks
   monopolising the Flask request workers with `GET /ingest/jobs/<id>`
   traffic — the very thing the async pipeline exists to avoid.
2. Cap `poll_timeout` at `600 s` for small SBOMs, `1800 s` for the
   largest expected payloads. If your SBOMs routinely take longer
   than that, raise `enrichment.ingest.concurrency` and `replicas`
   rather than the timeout.
3. Treat any 5xx response from `/ingest/jobs/<id>` as a poll failure,
   not a job failure. The job is still queued or running on the
   worker; retry the poll with exponential backoff.

Sample curl-loop (operations only — production clients should use the
SDK):

```bash
JOB=$(curl -sS -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "@sbom.json" https://api/ingest/cyclonedx \
       | jq -r .job_id)

while true; do
  STATE=$(curl -sS -H "Authorization: Bearer $TOKEN" \
                  https://api/ingest/jobs/$JOB | jq -r .state)
  echo "$(date -Is) state=$STATE"
  case "$STATE" in
    SUCCESS|FAILURE|REVOKED) break ;;
  esac
  sleep 2
done
```

### 4.3 Idempotency / retries

The HTTP contract is *not* idempotent: each `POST /ingest/*` produces
a fresh `record_id` and a fresh job, even for byte-identical bodies.
Clients that retry submission on network failure will produce
duplicate `SbomRecord` nodes. If that matters in your environment,
deduplicate at the caller using the SHA-256 of the SBOM body before
submitting; see `sbom_graph_enrichment.ingest_tasks._document_hash`
for the canonical hash function.

A future revision may add a server-side `If-None-Match: <hash>` style
guard; until then, idempotency is a caller responsibility.

---

## 5. Configuration reference

All knobs live in `helm/charts/sbom-graph/values.yaml` under the
`enrichment.ingest` block:

```yaml
enrichment:
  # Existing enrichment-worker block (queues: enrichment, celery)
  worker:
    enabled: true
    replicas: 1
    concurrency: 2
    # …

  # Dedicated ingest worker pool (new in §10.6).
  ingest:
    enabled: true        # set false to disable async ingest entirely
    replicas: 1
    concurrency: 2       # SBOMs in flight per pod -- see §2.2
    queueName: "ingest"  # MUST match the queue used by routes/ingest.py
    resources:
      limits:
        cpu: 1000m
        memory: 1Gi      # raised vs enrichment pool -- large SBOMs balloon in memory
      requests:
        cpu: 200m
        memory: 256Mi
```

### 5.1 Disabling the pool

Set `enrichment.ingest.enabled: false` (or `replicas: 0`) to disable
the dedicated worker pool. Effects:

- The `enrichment-ingest-worker` Deployment is not rendered.
- `POST /ingest/*` returns `503 Ingest pipeline not available`
  because nothing is listening on the `ingest` queue (the main
  enrichment pool does **not** pick it up automatically — that's the
  priority guarantee).
- `POST /ingest/*?sync=true` continues to work and is the only way to
  ingest in this mode.

This is the right configuration for very low-volume environments
(single-developer minikube clusters with `replicas: 0` for ingest +
all ingest via `?sync=true`) or during planned outages of the worker
pool.

### 5.2 Sizing rule of thumb

| SBOM size (JSON) | Typical parse-and-persist time | Per-task RSS peak | Suggested concurrency |
|---|---|---|---|
| < 1 MB | 1–3 s | 80–150 MiB | 2 |
| 1–10 MB | 5–30 s | 150–400 MiB | 2 |
| 10–50 MB | 30–180 s | 400 MiB – 1 GiB | 1 (with raised `limits.memory: 2Gi`) |

Always re-measure before raising concurrency; the numbers above
assume modest dependency fan-out. SBOMs with deep transitive trees
(npm front-ends, Python with extras) cost more memory per byte than
straight-line trees.

### 5.3 Liveness/readiness on the worker

The `enrichment-ingest-worker` Deployment uses Celery's built-in
liveness signals (`celery inspect ping` style) rather than an HTTP
probe — the worker has no HTTP listener. See
`helm/charts/sbom-graph/templates/enrichment-ingest-worker-deployment.yaml`
for the exact probe definition; it's identical to the enrichment
pool's probes and shouldn't need tuning unless you measure flapping.

---

## 6. Operational checks

### 6.1 Is the pool installed and healthy?

```bash
NS=sbom-graph
kubectl -n "$NS" get deploy -l app.kubernetes.io/component=enrichment-ingest-worker
kubectl -n "$NS" get pod    -l app.kubernetes.io/component=enrichment-ingest-worker
```

Expected: one Deployment, one Ready pod (per `replicas`).

### 6.2 Is the worker consuming from the `ingest` queue?

```bash
NS=sbom-graph
POD=$(kubectl -n "$NS" get pod \
        -l app.kubernetes.io/component=enrichment-ingest-worker \
        -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NS" logs "$POD" --tail=20 | grep -E 'ingest|queue'
```

Expected to see a startup line of the form
`celery@<pod> ready. queues = [ingest]` (or similar). If you see
queues other than `ingest`, the deployment template is misconfigured
— the dedicated pool MUST consume only `ingest`.

### 6.3 Submit a smoke-test SBOM

```bash
NS=sbom-graph
# A trivial CycloneDX 1.5 document, 1 component, no dependencies.
cat <<'EOF' > /tmp/smoke.cdx.json
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
 "metadata":{"component":{"type":"application","name":"smoke","version":"0.0.1"}},
 "components":[{"type":"library","name":"sample-lib","version":"1.0.0",
                "purl":"pkg:generic/sample-lib@1.0.0"}]}
EOF

kubectl -n "$NS" port-forward svc/sbom-graph-sbom-graph-api 8443:8443 &
PF=$!
sleep 2

RESP=$(curl -sS -k -H "Content-Type: application/json" \
            -d @/tmp/smoke.cdx.json \
            https://localhost:8443/ingest/cyclonedx)
echo "$RESP" | jq .
JOB=$(echo "$RESP" | jq -r .job_id)

# Poll until terminal:
for i in $(seq 1 30); do
  STATE=$(curl -sS -k https://localhost:8443/ingest/jobs/"$JOB" | jq -r .state)
  echo "poll $i: $STATE"
  case "$STATE" in SUCCESS|FAILURE) break ;; esac
  sleep 1
done

kill $PF
```

Expected: `accepted` ⇒ `STARTED` ⇒ `SUCCESS` within a couple of
seconds, with a `result.projects_count: 1`.

### 6.4 Quick API path sanity check

```bash
NS=sbom-graph
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[?(@.status.containerStatuses[0].ready==true)].metadata.name}' \
      | awk '{print $1}')
kubectl -n "$NS" logs "$POD" --tail=200 | grep -E 'ingest enqueued|ingest job'
```

Expected to see `SBOM ingest enqueued: record_id=… job_id=… task=…`
INFO lines for each smoke-test submission. If you see
`Ingest pipeline unavailable; falling back to synchronous processing`,
the API container can't import `sbom_graph_enrichment.ingest_tasks`
(see [§9](#9-troubleshooting-cross-reference)).

---

## 7. Threat model summary

A full threat model pass was done before implementation; this is the
operational subset. The new attack surface is:

1. **`POST /ingest/*` (async)** — same body shape and auth requirements
   as the legacy sync path. The 50 MB body limit (`MAX_SBOM_SIZE`)
   still applies and is enforced *before* the Celery `send_task`
   call. Validation is identical to the sync path, so payload-shape
   attacks reduce to the existing (already-tested) surface.
2. **`GET /ingest/jobs/<job_id>`** — protected by the same
   `@auth_required` decorator as the rest of the API. The handler
   validates the UUID shape up-front so an attacker cannot use it to
   probe arbitrary keys in the result-backend Redis namespace
   (CWE-22 / CWE-200). The response never includes raw exception
   details (CWE-209) — worker exceptions surface as the static string
   `"Ingest job failed; see server logs"` in the `result.error` field,
   and the actual exception is only ever in worker logs at WARNING.
3. **The `ingest` queue** — lives on the same Redis broker the
   enrichment pool already uses (DB 1). Authentication is the
   pre-existing Redis password on that broker; no new credentials are
   introduced. Network access to the broker is unchanged.
4. **Worker container** — runs the existing `sbom-graph-enrichment`
   image with the same security context (non-root, distroless). The
   only new code in the image is `sbom_graph_enrichment.ingest_tasks`,
   which is pure CPython and shares the same persistence layer
   (`sbom_graph_model.Persistence`) as the sync path. No new
   filesystem mounts, no new outbound network endpoints.

Findings (none blocking):

| Finding | Mitigation |
|---|---|
| Caller-controlled SBOM bodies are written to the broker as a Celery task payload. | The broker is in the same trust zone as the API + workers; bodies are not persisted to disk; the broker's MAXMEMORY policy reclaims them after `result_expires`. |
| Result-backend lookup uses a caller-supplied id. | Strict UUID validation in `GET /ingest/jobs/<id>` (CWE-22). |
| Worker exceptions could leak schema details via `state: FAILURE`. | Worker tasks catch their own validation exceptions and return a sanitised `{"status": "error", "error": "<safe message>"}` dict from `state: SUCCESS`; uncaught exceptions surface as the static generic message (CWE-209). |

---

## 8. Migration notes

| Client | Action required |
|---|---|
| `sbom-graph-cli` | None for CLI users; `push-sbom <file>` still does what it always did. Library users of `SBOMGraphClient.ingest_sbom()` should review the new `wait` / `sync` / `poll_*` kwargs — defaults preserve the old behaviour. |
| `sonatype-lifecycle-release-listener` | None **yet**. The listener still uses the synchronous path internally and is unaffected. Migration to the async path is tracked separately. |
| Third-party HTTP clients | If you currently rely on a `201 Created` response code, either pass `?sync=true` (legacy behaviour preserved) or update the client to handle `202` + poll. See [§4.2](#42-http-direct-clients-sonatype-listener-ad-hoc-curl). |

A grep for hard-coded status codes in your callers:

```bash
rg -n 'status[_ ]code\s*==\s*201|HTTPStatus\.CREATED' your-repo/
```

If those callers POST to `/ingest/*`, they need to learn about `202`
or be pinned to `?sync=true`.

---

## 9. Troubleshooting cross-reference

| Symptom | Where to look |
|---|---|
| `POST /ingest/*` returns `202` but `result_id` never appears in graph | [§6.2](#62-is-the-worker-consuming-from-the-ingest-queue) — is the worker actually consuming the `ingest` queue? |
| `POST /ingest/*` returns `503` | API can't import `sbom_graph_enrichment.celery_app`. Check that the API image was built with the enrichment package, or use `?sync=true`. |
| `GET /ingest/jobs/<id>` returns `PENDING` forever | Either the worker isn't consuming the queue ([§6.2](#62-is-the-worker-consuming-from-the-ingest-queue)) **or** the job id is unknown to the result backend (Celery limitation — unknown ids return `PENDING`). Confirm against the API log which prints `job_id=` on enqueue. |
| Worker pod OOMKilled mid-ingest | Reduce `enrichment.ingest.concurrency` or raise `enrichment.ingest.resources.limits.memory`. See [§5.2](#52-sizing-rule-of-thumb). |
| API liveness-probe failures reappear | Confirm callers aren't pinned to `?sync=true`. Grep API logs for the `Ingest pipeline unavailable; falling back to synchronous processing` warning. See [`sbom-graph-api-troubleshooting.md` §10](./sbom-graph-api-troubleshooting.md#10-ingest-induced-liveness-probe-timeouts). |
| Worker pod restarts cleanly mid-job | Celery acks the task only on success; the next worker picks it up. With `--prefetch-multiplier=1` only one task at a time is in-flight per slot, so a restart loses at most `concurrency` jobs which the broker re-queues automatically. |

Related guides:

- [`sbom-graph-api-troubleshooting.md`](./sbom-graph-api-troubleshooting.md)
  — the surrounding API operational guide; §10 is the failure pattern
  this pipeline eliminates.
- [`falkordb-backup-and-restore.md`](./falkordb-backup-and-restore.md)
  — FalkorDB persistence and the `THREAD_COUNT=1` mitigation that
  shapes how long an individual ingest task takes.
