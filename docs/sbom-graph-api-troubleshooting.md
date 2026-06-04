# `sbom-graph-api` troubleshooting

This guide explains how to diagnose and recover the `sbom-graph-api` Flask /
Gunicorn process when its container restarts unexpectedly — most commonly while
serving the heavier report endpoints (`/reports/vulnerabilities`,
`/reports/incident-response/...`, `/reports/vex-coverage`, etc.).

If the symptom is a stuck or failing FalkorDB snapshot, see
[`falkordb-backup-and-restore.md`](./falkordb-backup-and-restore.md) instead —
that's the persistence layer, not the API.

Audience: cluster operators / admins running the `sbom-graph` Helm release.

Tested namespace in examples: `sbom-graph`. Substitute your own if different.

---

## Table of contents

1. [How the API processes FalkorDB results](#1-how-the-api-processes-falkordb-results)
2. [First-pass triage](#2-first-pass-triage)
3. [Confirm the exact kill reason](#3-confirm-the-exact-kill-reason)
4. [Live memory monitoring (no metrics-server, distroless image)](#4-live-memory-monitoring-no-metrics-server-distroless-image)
5. [Why the report endpoints are the usual culprit](#5-why-the-report-endpoints-are-the-usual-culprit)
6. [Immediate mitigation: raise the memory limit](#6-immediate-mitigation-raise-the-memory-limit)
7. [Verifying the fix](#7-verifying-the-fix)
8. [Sizing rule of thumb](#8-sizing-rule-of-thumb)
9. [Other crash patterns and how to tell them apart](#9-other-crash-patterns-and-how-to-tell-them-apart)
10. [Ingest-induced liveness-probe timeouts](#10-ingest-induced-liveness-probe-timeouts)
11. [Long-term fix: pagination / streaming](#11-long-term-fix-pagination--streaming)
12. [Reference](#12-reference)

---

## 1. How the API processes FalkorDB results

The Flask app talks to FalkorDB via the Python `redis` client over mTLS. For
every report endpoint the flow is the same:

1. The route handler calls a method on `FalkorDbService`
   (`sbom-graph-api/src/sbom_graph_api/services/falkordb_service.py`).
2. The service builds a Cypher query and executes it via
   `GRAPH.QUERY <graphName> "…"`.
3. FalkorDB returns the **entire** result set in one response — there is no
   server-side cursor like Postgres has. The client library materialises every
   row as a Python dict in a list before the call returns.
4. The route handler iterates the list to compute counts, then either
   - renders the list into a single HTML page with Jinja, or
   - converts it to JSON, or
   - builds an Excel workbook in memory.
5. The response object holds the full rendered payload until the kernel hands
   it to the socket.

Peak memory therefore equals **(Python list of dicts) + (Jinja render buffer)
+ (Gunicorn baseline)**. For the largest report —
`/reports/vulnerabilities` — that grows roughly linearly with the number of
distinct `Defect` nodes and their collected `affected_versions`.

The relevant code paths:

- `sbom-graph-api/src/sbom_graph_api/routes/reports/vulnerabilities.py`
  — endpoint handlers (`all_vulnerabilities`, `incident_response`, etc.).
- `sbom-graph-api/src/sbom_graph_api/services/falkordb_service.py`
  — Cypher queries (`get_all_vulnerabilities` around line 2186, plus
  `get_vulnerability_dependants`, `get_blast_radius`, …).
- `sbom-graph-api/gunicorn.conf.py` — workers / threads / timeouts.
- `helm/charts/sbom-graph/values.yaml` → `sbomGraphApi.resources` — cgroup
  request/limit (the kernel is the one that enforces OOM).
- `helm/charts/sbom-graph/templates/sbom-graph-api-deployment.yaml` —
  liveness/readiness probes, mounts, env vars.

---

## 2. First-pass triage

When the API "keeps crashing", run the four-step block below. It captures
everything you need to choose between *"raise the limit"*, *"raise concurrency"*,
or *"there's a Python exception"* without further round-trips.

```bash
NS=sbom-graph

echo "=== 1. Current pod state (look for restart counts and CrashLoopBackOff) ==="
kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api -o wide

echo
echo "=== 2. Recent events for the api deployment ==="
kubectl -n "$NS" get events --sort-by=.lastTimestamp \
  --field-selector involvedObject.kind=Pod 2>/dev/null \
  | grep -E "sbom-graph-api|^LAST|Killed|OOM|Liveness|Readiness|Backoff" | tail -25

echo
echo "=== 3. Logs from the LIVE pod (last 150 lines) ==="
kubectl -n "$NS" logs -l app.kubernetes.io/component=sbom-graph-api --tail=150

echo
echo "=== 4. Logs from the PREVIOUS pod, if there was a restart ==="
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
  -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$NS" logs "$POD" --previous --tail=150 2>/dev/null \
  || echo "(no previous pod — first start)"
```

What each row tells you:

| Output | What it tells you |
|---|---|
| `RESTARTS` > 0 in step 1 | The container is being killed and restarted — go to step 2/3. |
| `Warning  BackOff … Back-off restarting failed container` in step 2 | Kubelet has noticed the failure pattern and is throttling restarts. |
| `Killing` events without `OOMKilled` reason | Liveness probe failure or graceful stop. |
| `OOMKilled` reason in step 2 | Container exceeded its cgroup memory limit. Go to [§6](#6-immediate-mitigation-raise-the-memory-limit). |
| Gunicorn `WORKER TIMEOUT` in logs | Worker exceeded `GUNICORN_TIMEOUT` (default 300 s). See [§9](#9-other-crash-patterns-and-how-to-tell-them-apart). |
| Python traceback in logs | Application bug — fix the code; not a config issue. |
| Live logs show only `/health 200` and no /reports request | The worker died mid-request before logging completion — strong signal of OOM. |
| `Invalid request from ip=127.0.0.1: SSLV3_ALERT_CERTIFICATE_UNKNOWN` | Harmless startup noise from the wait-for-falkordb init container probing the TLS endpoint. Not a crash cause. |

---

## 3. Confirm the exact kill reason

The Pod's `events` array sometimes doesn't include `OOMKilled` even when the
kernel did the killing — the authoritative answer is in
`containerStatuses[0].lastState.terminated.reason`.

```bash
NS=sbom-graph
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
  -o jsonpath='{.items[0].metadata.name}')

echo "=== lastState (look for reason: OOMKilled vs Error vs Completed) ==="
kubectl -n "$NS" get pod "$POD" -o json | \
  python3 -c "import sys,json; p=json.load(sys.stdin); \
[print(json.dumps(c.get('lastState',{}), indent=2)) \
 for c in p['status']['containerStatuses'] if c['name']=='sbom-graph-api']"

echo
echo "=== Configured memory request/limit ==="
kubectl -n "$NS" get pod "$POD" -o json | \
  python3 -c "import sys,json; p=json.load(sys.stdin); \
[print(json.dumps(c.get('resources',{}), indent=2)) \
 for c in p['spec']['containers'] if c['name']=='sbom-graph-api']"
```

A textbook OOM looks like this:

```json
{
  "terminated": {
    "containerID": "containerd://…",
    "exitCode": 137,
    "finishedAt": "2026-05-29T18:56:38Z",
    "reason": "OOMKilled",
    "startedAt": "2026-05-29T18:56:19Z"
  }
}
```

Note the **19 seconds** between `startedAt` and `finishedAt` and **exit code
137** (= `128 + SIGKILL`). That timestamp gap, plus an `OOMKilled` reason, plus
the absence of a Python traceback in the logs, is the unambiguous signature of
the container's cgroup running out of memory while a worker was building a
response.

If you see `Error` or no `lastState` at all, jump to
[§9](#9-other-crash-patterns-and-how-to-tell-them-apart).

---

## 4. Live memory monitoring (no metrics-server, distroless image)

The API image (`gcr.io/distroless/python3-debian13`) is distroless: it ships only
`python` and the application. There is **no `/bin/sh`, no `cat`, no `printf`**,
so `kubectl exec -- sh -c '…'` exits immediately. Drive the probe through
Python instead:

```bash
NS=sbom-graph
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
  -o jsonpath='{.items[0].metadata.name}')

while true; do
  clear
  date
  kubectl -n "$NS" exec "$POD" -c sbom-graph-api -- python -c '
import os
for used_path, max_path in [
    ("/sys/fs/cgroup/memory.current",            "/sys/fs/cgroup/memory.max"),
    ("/sys/fs/cgroup/memory/memory.usage_in_bytes",
                                                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"),
]:
    if os.path.exists(used_path):
        used  = int(open(used_path).read())
        limit = open(max_path).read().strip()
        try:
            limit_mib = f"{int(limit) // 1048576} MiB"
        except ValueError:
            limit_mib = limit  # cgroup v2 prints "max" when unlimited
        print(f"used: {used // 1048576} MiB / limit: {limit_mib}")
        break
'
  sleep 1
done
```

`memory.current` (cgroup v2) and `memory.usage_in_bytes` (cgroup v1) are the
exact bytes the kernel will compare against the limit when deciding to kill the
container, so this matches reality — there is no scrape interval to worry
about.

Easier alternatives if you'd rather use standard tooling:

| Approach | One-liner |
|---|---|
| `kubectl top` | `minikube addons enable metrics-server` once, then `kubectl -n sbom-graph top pod -l app.kubernetes.io/component=sbom-graph-api --containers` |
| Node-side | `minikube ssh` → `sudo crictl stats` (no in-container shell needed) |

Hit `/reports/vulnerabilities` (or whichever endpoint crashed) while the loop
runs. You'll see memory climb in the second or two before it either succeeds or
hits the limit.

---

## 5. Why the report endpoints are the usual culprit

The single largest report is `/reports/vulnerabilities`. The Cypher query
behind `FalkorDbService.get_all_vulnerabilities` returns **one row per `Defect`
node**, with each row carrying a `collect(DISTINCT { … })` of every affected
version and (when present) of every VEX statement. The route handler then:

1. Materialises that result set into a Python `list[dict]`.
2. Walks the list to compute VEX coverage and severity counts.
3. Optionally filters by `vex_filter`.
4. Passes the whole list to `render_template("vulnerabilities.html", …)`,
   which builds one big HTML string containing the entire table.

On a moderately populated graph this works fine. On a fully ingested graph it
explodes. The actual numbers from the incident that produced this guide:

```
MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect) RETURN count(d), count(DISTINCT d)
→ count(d)         : 54221
→ count(DISTINCT d): 14597
Query internal execution time: 21.657 ms
```

i.e. ~14.6 k distinct `Defect` rows with an average of ~3.7 affected-version
entries each. FalkorDB itself returned in **21 ms**; the rest of the time was
Python building dicts and Jinja rendering HTML. Empirical resident-memory cost
on that dataset was **~10 KB per row** before rendering, plus a ~100 MB
Flask/Gunicorn baseline and a comparable Jinja render buffer for the response
string. Total peak: ~1.5 GiB.

When the cgroup limit was the chart default of **512 MiB**, the kernel killed
the container ~19 seconds into the request, before the worker could log
completion. Symptoms looked exactly like the pattern in
[§2](#2-first-pass-triage):

- `RESTARTS` incrementing on the API pod every ~90 s.
- `Back-off restarting failed container sbom-graph-api` events.
- No traceback in the previous-pod logs — just startup, a `/health 200`, then
  silence.
- `/health` continued to return 200 from sibling worker threads, masking the
  failure until the response that triggered it was abandoned.

The same shape applies (less dramatically) to:

| Endpoint | Heavy because |
|---|---|
| `/reports/vulnerabilities` | All defects + collected affected versions + VEX. |
| `/reports/incident-response/<id>` | Blast radius traversal + patch plan in one render. |
| `/reports/vulnerability-dependants/<id>` | Variable-depth traversal returning a per-dependant row. |
| `/reports/vex-coverage` | Materialises every vulnerability with VEX joined. |
| `/reports/enrichment-coverage` | All packages + status classification. |

Excel and JSON formats on the same routes have the **same peak memory cost**
as the HTML format — the underlying list is identical; only the final
serialiser differs.

---

## 6. Immediate mitigation: raise the memory limit

If [§3](#3-confirm-the-exact-kill-reason) confirmed `OOMKilled`, the
operational fix is to raise `sbomGraphApi.resources.limits.memory` in
`helm/charts/sbom-graph/values.yaml`:

```yaml
sbomGraphApi:
  # Memory sizing notes:
  #   The /reports/vulnerabilities endpoint currently materialises every Defect
  #   row (with its collected affected_versions and vex_statements) into a single
  #   Python list before rendering one HTML page.  Empirically this costs
  #   ~10 KB/row of resident memory, plus a ~100 MB Flask/Gunicorn baseline and
  #   a comparable Jinja render buffer for the response.  Sizing rule of thumb:
  #     limit_MiB >= 250 + ceil(rows / 100)
  #   so 14 k vulnerabilities needs >= ~1.7 GiB to render safely.  Raise this
  #   further if you grow the graph or hit OOMKilled (exit 137) on report endpoints.
  #   The proper long-term fix is server-side pagination of the report
  #   (see §10 of docs/sbom-graph-api-troubleshooting.md).
  resources:
    limits:
      cpu: 1500m
      memory: 2Gi
    requests:
      cpu: 250m
      memory: 256Mi
```

Why these specific numbers:

| Setting | Value | Why |
|---|---|---|
| `memory` limit | **2 Gi** | ~3× the observed peak for a ~14.6 k-row report. Headroom for graph growth and concurrent requests. |
| `memory` request | 256 Mi | A truthful steady-state signal for the scheduler without reserving the worst-case footprint. |
| `cpu` limit | 1500 m | Python list construction + Jinja rendering on 10 k+ rows is CPU-bound during the response. 500 m turned a sub-second render into many seconds and gave the 10 s `timeoutSeconds` on `/health` almost no margin. |
| `cpu` request | 250 m | Matches the steady-state under a running report. |

Apply it:

```bash
cd /path/to/repo
helm upgrade --install sbom-graph helm/charts/sbom-graph -n sbom-graph
kubectl -n sbom-graph rollout status deploy/sbom-graph-sbom-graph-api --timeout=180s
```

---

## 7. Verifying the fix

After the rollout, confirm both that the new limits took effect and that the
new pod is stable (no restarts under load).

```bash
NS=sbom-graph
kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].restartCount}{"\trestarts\n"}{end}'
kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
  -o jsonpath='{.items[0].spec.containers[0].resources}{"\n"}'
```

Expected after the fix described in [§6](#6-immediate-mitigation-raise-the-memory-limit):

```
sbom-graph-sbom-graph-api-<rs>-<pod>	0	restarts
{"limits":{"cpu":"1500m","memory":"2Gi"},"requests":{"cpu":"250m","memory":"256Mi"}}
```

Then hit the endpoint that was crashing and confirm:

- HTTP status is 200 and the response renders fully.
- The restart count stays at 0 across multiple requests.
- `lastState` is no longer populated, or — if it is — its `reason` is from
  *before* the rollout (compare `finishedAt` to the rollout time).

If you ran the cgroup memory loop from [§4](#4-live-memory-monitoring-no-metrics-server-distroless-image)
in another terminal you should see the peak well below the new limit. If peak
is creeping toward 80% of the limit, plan the next bump using the rule below.

---

## 8. Sizing rule of thumb

For the report endpoints that materialise the full result set:

```
limit_MiB >= 250 + ceil(rows / 100)
```

| Distinct `Defect` rows | Minimum limit | Recommended limit |
|---|---|---|
| 1 000 | ~260 MiB | 512 MiB |
| 5 000 | ~300 MiB | 768 MiB |
| 14 600 (incident snapshot) | ~396 MiB | **2 GiB** (current default — 5× safety) |
| 30 000 | ~550 MiB | 2 GiB |
| 75 000 | ~1 GiB | 3 GiB *and* implement pagination — see [§10](#10-long-term-fix-pagination--streaming) |
| 150 000+ | not viable | pagination is mandatory; raising the limit is no longer enough |

To check the current row counts in your cluster (no API restart required):

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" \
    GRAPH.QUERY acme-corp \
    "MATCH (d:Defect) RETURN count(DISTINCT d) AS distinct_defects" --no-raw
  redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" \
    GRAPH.QUERY acme-corp \
    "MATCH (v:Version)-[:VERSION_DEFECT]->(d:Defect) RETURN count(*) AS edges" --no-raw
'
```

Plug `distinct_defects` into the formula above and compare to the current
`limits.memory` from [§7](#7-verifying-the-fix).

---

## 9. Other crash patterns and how to tell them apart

| `lastState.reason` | Logs say… | Likely cause | Fix direction |
|---|---|---|---|
| `OOMKilled` (exit 137) | No traceback; container ends mid-request | Cgroup memory exceeded | [§6](#6-immediate-mitigation-raise-the-memory-limit) |
| `Error` (exit 137) | Logs end cleanly **without** an `OOMKilled` event; events table shows `Container … failed liveness probe, will be restarted` and `context deadline exceeded` on `/health` | Kubelet SIGKILL after the liveness probe consecutively timed out — the pod was *healthy* but its workers were saturated by long synchronous requests (typically SBOM ingest). Since [§10.6](#106-architectural-fix-async-ingest-on-a-dedicated-worker-pool) shipped this should only recur if ingest jobs are being forced through the `?sync=true` escape hatch. | [§10](#10-ingest-induced-liveness-probe-timeouts) |
| `Error` (exit 1) | Python traceback or `ImportError` at startup | Application bug or bad config | Fix the code / config |
| `Error` (exit other) | `WORKER TIMEOUT` from gunicorn master | A single request exceeded `GUNICORN_TIMEOUT` (default 300 s); usually a slow Cypher query | Raise `GUNICORN_TIMEOUT` env var **and** investigate the slow query in FalkorDB (see [`falkordb-backup-and-restore.md` §5](./falkordb-backup-and-restore.md#5-diagnose-and-recover-a-stuck-snapshot) for `THREAD_COUNT` context) |
| `Error` (exit other) | `Connection refused` / `ConnectionError` to FalkorDB | FalkorDB is down or unreachable | Check FalkorDB pod & service; the wait-for-falkordb init container should normally catch this |
| `Completed` (exit 0) | Clean gunicorn shutdown messages | Pod deleted / rolled / SIGTERM from the deployment controller | No action — it's a normal restart |
| *(no lastState)* | n/a | First start ever, or container hasn't terminated yet | n/a |

> **Note on exit 137.** Both `OOMKilled` and a kubelet-initiated SIGKILL after a
> failed liveness probe produce `exitCode: 137` — the difference is in the
> *reason*. If `lastState.reason == "OOMKilled"`, the kernel killed it for
> exceeding the memory cgroup. If `lastState.reason == "Error"` (or empty) and
> the events table shows `Liveness probe failed`, the kubelet killed it — see
> [§10](#10-ingest-induced-liveness-probe-timeouts).

Two non-fatal log lines that look alarming but aren't:

- `[WARNING] Invalid request from ip=127.0.0.1: SSLV3_ALERT_CERTIFICATE_UNKNOWN`
  — the wait-for-falkordb init container or some other in-pod startup check
  performed a TLS handshake against `127.0.0.1:8443` without trusting the
  self-signed server cert. Harmless.
- `[INFO] "GET /health HTTP/1.1" 200 21 "-" "kube-probe/<ver>"` every 10 s —
  kubelet's readiness probe, working as intended.

---

## 10. Ingest-induced liveness-probe timeouts

This is the second-most-common API crash after the report-endpoint OOM
covered in [§5](#5-why-the-report-endpoints-are-the-usual-culprit)/[§6](#6-immediate-mitigation-raise-the-memory-limit).
Externally it looks like the API is "crashing during ingest" — often surfaced
as a `kubectl port-forward` `error: lost connection to pod` / `broken pipe`
message and a fresh restart count on the API pod.

### 10.1 What's actually happening

The `sbom-graph-api` container runs Gunicorn with the **gthread** worker
class, defaulting to 2 workers × 2 threads = **4 in-flight requests per
pod**. The pod has two probes against `/health`:

- **readinessProbe**: `httpGet /health` every 10 s, `timeoutSeconds: 20`,
  `failureThreshold: 3` → up to 90 s of unresponsiveness flips the pod out
  of the Service.
- **livenessProbe**: `httpGet /health` every 30 s, `timeoutSeconds: 30`,
  `failureThreshold: 5` → up to **5 × (30 s + 30 s) = 300 s** of consecutive
  failures before the kubelet SIGKILLs the container. (These are the *tuned*
  values applied to address this pattern — see [§10.4](#104-the-fix).)

`/health` itself does **nothing** — it's a static `jsonify({"status": "ok"})`.
But it still has to be *scheduled onto a worker thread* to be served. If all
4 gthread slots are occupied by an in-progress `POST /ingest/cyclonedx`
or `POST /ingest/spdx` — each of which spends multiple seconds parsing the
SBOM in pure Python and then issuing dozens of `GRAPH.QUERY` writes over
mTLS — the probe request *queues*. When it queues longer than
`timeoutSeconds`, the kubelet records a probe failure even though the
process is perfectly healthy.

A run of consecutive failures past `failureThreshold` is treated as a
liveness violation, and the kubelet sends SIGKILL. That kill is what
breaks any open `kubectl port-forward`, producing the "broken pipe" the
operator sees.

### 10.2 How to recognise it

The signature is:

- `kubectl get pod` shows a fresh restart on the API pod.
- `kubectl describe pod <pod>` (or the events table) contains:
  ```
  Warning  Unhealthy  Liveness probe failed: Get "https://.../health": context deadline exceeded
  Normal   Killing    Container sbom-graph-api failed liveness probe, will be restarted
  ```
- `lastState.terminated.reason == "Error"` (not `OOMKilled`) and
  `exitCode == 137`.
- The container's logs *just before* the kill show normal `200`-status
  request lines — no traceback, no `WORKER TIMEOUT` from the gunicorn
  master, no OOM line from the kernel.
- Live cgroup memory (from the procfs script in [§4](#4-live-memory-monitoring-no-metrics-server-distroless-image))
  is well below the configured limit. This rules out OOM.

The single most diagnostic command is:

```bash
NS=sbom-graph
kubectl -n "$NS" get events --sort-by=.lastTimestamp \
  --field-selector involvedObject.kind=Pod 2>/dev/null \
  | grep -E "sbom-graph-api|^LAST" | tail -20
```

If you see `Liveness probe failed: ... context deadline exceeded` followed
by `Killing` without any `OOMKilling` event in between, this section is
your answer.

### 10.3 Why ingest in particular is the trigger

A typical SBOM ingest request:

1. Parses CycloneDX / SPDX JSON into Python dicts (CPU-bound, GIL-held).
2. Walks the parse tree and issues many `GRAPH.QUERY` writes via the redis
   client over mTLS. Each round-trip is a TCP write + TLS frame + Cypher
   parse + graph mutation on the FalkorDB side. With `THREAD_COUNT=1` /
   `OMP_THREAD_COUNT=1` (the persistence-stability mitigation from
   [`falkordb-backup-and-restore.md` §5](./falkordb-backup-and-restore.md#5-diagnose-and-recover-a-stuck-snapshot)),
   writes are serialised on the database side.
3. For a medium SBOM (a few thousand components and dependencies) this
   easily holds a single Gunicorn thread for 30–90 s.

Two concurrent ingests therefore occupy 2 of 4 slots; three occupy 3 of 4;
four wedge the pod against all four probes for as long as the slowest one
takes to finish. The pod isn't broken — it's just too busy to answer trivia.

### 10.4 The fix

Two complementary levers. **Lever A** is the change applied here. Lever B
is documented for later, when ingest volume increases further.

**A. Give the probes enough headroom to ride out an ingest burst.**

`helm/charts/sbom-graph/templates/sbom-graph-api-deployment.yaml`:

```yaml
readinessProbe:
  httpGet:
    path: /health
    port: http
    scheme: HTTPS
  initialDelaySeconds: 15
  periodSeconds: 10
  timeoutSeconds: 20     # was 10
  failureThreshold: 3
livenessProbe:
  httpGet:
    path: /health
    port: http
    scheme: HTTPS
  initialDelaySeconds: 30
  periodSeconds: 30
  timeoutSeconds: 30     # was 10
  failureThreshold: 5    # was default 3
```

This raises the time a saturated pod can be unresponsive before kubelet
kills it from `3 × (10 s + 30 s) = 90 s` to `5 × (30 s + 30 s) = 300 s`,
comfortably above the longest ingest bursts we've seen on the current
graph. Readiness still flips at 90 s, which is fine — it just stops new
traffic until the worker pool drains.

Apply with:

```bash
helm upgrade sbom-graph helm/charts/sbom-graph -n sbom-graph --reuse-values
kubectl -n sbom-graph rollout status deploy/sbom-graph-sbom-graph-api
```

Verify it's live:

```bash
NS=sbom-graph
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=sbom-graph-api \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[?(@.status.containerStatuses[0].ready==true)].metadata.name}' \
      | awk '{print $1}')
kubectl -n "$NS" get pod "$POD" \
  -o jsonpath='{.spec.containers[?(@.name=="sbom-graph-api")].livenessProbe}'; echo
kubectl -n "$NS" get pod "$POD" \
  -o jsonpath='{.spec.containers[?(@.name=="sbom-graph-api")].readinessProbe}'; echo
```

You should see `"timeoutSeconds":30,"failureThreshold":5` on the liveness
probe and `"timeoutSeconds":20` on the readiness probe.

**B. Raise per-pod concurrency (optional, when A isn't enough).**

The deeper fix is to add more slots so probes don't have to wait at all.
`sbom-graph-api/gunicorn.conf.py` reads two env vars:

```yaml
# helm/charts/sbom-graph/values.yaml (excerpt)
sbomGraphApi:
  gunicornWorkers: "2"
  # GUNICORN_THREADS is set via env in the deployment template
```

Bumping `GUNICORN_THREADS` from `2` → `4` doubles in-flight capacity per
pod (`2 workers × 4 threads = 8 slots`) at a roughly 30–60 MiB per extra
thread RAM cost. Only do this *after* A, and re-check cgroup memory under
load with [§4](#4-live-memory-monitoring-no-metrics-server-distroless-image)
to make sure the higher concurrency doesn't push the pod toward the 2 GiB
ceiling.

### 10.5 Why we don't just disable the liveness probe

A liveness probe still earns its keep when the worker is genuinely
deadlocked (e.g. a Cypher write stuck behind a fork-deadlocked BGSAVE — see
[`falkordb-backup-and-restore.md` §5](./falkordb-backup-and-restore.md#5-diagnose-and-recover-a-stuck-snapshot)).
The 300 s budget after [§10.4 A](#104-the-fix) is long enough that no
healthy ingest bursts can trip it, but short enough that an *actual* hang
is still recovered within five minutes.

### 10.6 Architectural fix: async ingest on a dedicated worker pool

> **Status: implemented.** The full operator + developer guide lives in
> [`docs/ingest-pipeline.md`](./ingest-pipeline.md). This subsection is the
> troubleshooting-side summary — what changed, how it eliminates this
> failure class, and how to spot regressions.

Moving ingest off the Flask request path entirely eliminates this class of
failure altogether. The implementation has three pieces:

1. **`POST /ingest/*` returns `202 Accepted` by default.** The Flask
   handler validates the payload (size, schema, format autodetect for
   `/ingest/sbom`) and enqueues a Celery task carrying the parsed JSON.
   Total wall-clock on the request thread: low tens of milliseconds.
   The response body is:

   ```json
   {
     "status": "accepted",
     "record_id": "<uuid>",
     "job_id": "<celery-task-id>",
     "status_url": "/ingest/jobs/<celery-task-id>",
     "format": "cyclonedx"
   }
   ```

   plus a `Location: /ingest/jobs/<id>` header.  Clients poll
   `GET /ingest/jobs/<id>` until `terminal: true`, then read `result` for
   the same summary the legacy synchronous path returned (`projects_count`,
   `dependencies_count`, `defects_count`, …).

2. **A dedicated `ingest` Celery queue with its own worker pool.** The
   existing enrichment worker stays on the `enrichment` queue;  a new
   deployment (`enrichment-ingest-worker`, see `helm/charts/sbom-graph/
   templates/enrichment-ingest-worker-deployment.yaml`) listens *only*
   on the `ingest` queue with `--prefetch-multiplier=1` so a single
   large SBOM can never block a small one.  This is the priority
   guarantee the operator asked for: ingest jobs cannot be starved by
   long-running enrichment scans, and vice versa.

3. **Synchronous escape hatch.**  `POST /ingest/*?sync=true` still
   processes inline and returns `201` with the legacy summary directly.
   Use it for small SBOMs in test scripts, or when the ingest worker
   pool is intentionally disabled (`enrichment.ingest.enabled: false`).
   The same code path runs the same `process_*` helpers as the worker,
   so behaviour is identical apart from the HTTP envelope.

**Effect on this failure class.** The Flask request thread no longer
holds a gthread slot for the full parse-and-persist cost of an SBOM —
it holds it for the duration of the JSON validation and the
`celery.send_task` call (single Redis `LPUSH`). All four gthread slots
stay free for `/health` and report traffic.  The kill-via-liveness
pattern this whole section describes is structurally impossible while
the ingest worker pool is the one doing the work.

**Spotting regressions.** If `POST /ingest/*` ever returns `201` from a
production deployment that has `enrichment.ingest.enabled: true`, it
means either:

- the caller passed `?sync=true` explicitly (legitimate — confirm with
  the caller), OR
- the API container couldn't import `sbom_graph_enrichment.ingest_tasks`
  and silently fell back to the synchronous path (broken). In the
  second case the API log line at request time will read
  `Ingest pipeline unavailable; falling back to synchronous processing`
  at WARNING level.

The CLI defaults to `--wait` and polls behind the spinner, so existing
`sbom-graph push-sbom <file>` scripts keep working with no flag
changes; pass `--no-wait` for fire-and-forget submission in CI/CD.

The recommended operational follow-up — server-side pagination of the
report endpoints — is still independent of this work; see
[§11](#11-long-term-fix-pagination--streaming).

---

## 11. Long-term fix: pagination / streaming

Raising the memory limit ([§6](#6-immediate-mitigation-raise-the-memory-limit))
is a stopgap. As the SBOM graph grows, three pressures keep biting:

1. **`get_all_vulnerabilities()` materialises every row in Python.** A
   streamed cursor (yield-per-row → write to the response in chunks) would cap
   peak memory at roughly one row at a time. FalkorDB doesn't have native
   cursors, but the same effect can be achieved server-side with
   `MATCH … SKIP $offset LIMIT $page` looped from the caller.
2. **The HTML template renders every row at once.** Even with paginated data,
   the current template iterates the entire list. Adding `?page=` /
   `?per_page=` query params on the route, plus prev/next links in the
   template, would fix the symptom permanently. The existing JSON and Excel
   paths can keep returning the full dataset (those are explicit downloads).
3. **The query itself is O(V × D)** where `V` is the count of
   `Version → Defect` edges and `D` is distinct defects. Each row carries a
   `collect(DISTINCT {…})` of every affected version, fanning the result set
   out. Adding `LIMIT` and `ORDER BY` server-side cuts both wall time and
   bytes transferred.

Sketch of the change (≈30 lines, in
`sbom-graph-api/src/sbom_graph_api/routes/reports/vulnerabilities.py`):

```python
from sbom_graph_api.utils.validation import validate_pagination_params

page, per_page = validate_pagination_params(
    request.args.get("page"),
    request.args.get("per_page"),
    default_per_page=100,
    max_per_page=1000,
)

vulns, total = service.get_all_vulnerabilities(
    internal_only,
    defect_id_match,
    skip=(page - 1) * per_page,
    limit=per_page,
)
```

…with a matching `SKIP $skip LIMIT $limit` in the underlying Cypher and a
`COUNT(*)` companion query for the total. The JSON and Excel paths can keep
calling the existing unpaginated method (or accept a `?full=true` parameter
that streams to disk before responding).

This is the recommended next step once the immediate operational pain is
resolved. Until then, the 2 GiB limit + 1500 m CPU sizing from
[§6](#6-immediate-mitigation-raise-the-memory-limit) carries any graph up to
roughly 75 k distinct vulnerabilities — see [§8](#8-sizing-rule-of-thumb).

---

## 12. Reference

API-side configuration that affects the failure modes covered above:

| Setting | File | Default | Purpose |
|---|---|---|---|
| `sbomGraphApi.resources.limits.memory` | `helm/charts/sbom-graph/values.yaml` | `2Gi` | Hard cgroup memory limit; exceeding it ⇒ OOMKilled. |
| `sbomGraphApi.resources.limits.cpu` | same | `1500m` | CPU ceiling; too low slows Python/Jinja render and risks probe timeouts. |
| `sbomGraphApi.resources.requests.memory` | same | `256Mi` | Scheduler signal only. |
| `sbomGraphApi.resources.requests.cpu` | same | `250m` | Scheduler signal only. |
| `sbomGraphApi.gunicornWorkers` | same | `"2"` | Number of Gunicorn worker processes. Each worker has its own memory footprint. |
| `GUNICORN_THREADS` | `sbom-graph-api/gunicorn.conf.py` env | `2` | Threads per worker (gthread). Total concurrency = workers × threads. |
| `GUNICORN_TIMEOUT` | same | `300` (s) | Per-request wall-clock limit before the master kills the worker. |
| `livenessProbe` | `helm/charts/sbom-graph/templates/sbom-graph-api-deployment.yaml` | `httpGet /health`, `periodSeconds: 30`, `timeoutSeconds: 30`, `failureThreshold: 5` | `/health` is a static jsonify — does not touch FalkorDB — but still needs a free gthread slot. Tuned to ride out concurrent ingest bursts; see [§10](#10-ingest-induced-liveness-probe-timeouts). |
| `readinessProbe` | same | `httpGet /health`, `periodSeconds: 10`, `timeoutSeconds: 20`, `failureThreshold: 3` | Flips the pod out of the Service if it stops responding for ~90 s; rejoins automatically when `/health` is reachable again. |

Useful commands beyond what the sections above already showed:

- `kubectl -n sbom-graph describe pod <pod>` — full Pod spec + events + last
  termination state in one view.
- `kubectl -n sbom-graph logs <pod> -c sbom-graph-api -f` — follow live logs.
- `kubectl -n sbom-graph logs <pod> -c sbom-graph-api --previous` — logs from
  the previously-killed instance of the container (often the only place the
  cause is visible).
- `kubectl -n sbom-graph rollout history deploy/sbom-graph-sbom-graph-api` —
  see when the deployment was last upgraded.
- `helm -n sbom-graph history sbom-graph` — Helm-level history including
  values changes.

Related operational guides:

- [`ingest-pipeline.md`](./ingest-pipeline.md) — design, configuration, and
  client-side conventions for the asynchronous ingest pipeline introduced
  in §10.6. Required reading before changing the ingest queue topology,
  worker concurrency, or the `?sync=true` escape hatch.
- [`falkordb-backup-and-restore.md`](./falkordb-backup-and-restore.md) — for
  the FalkorDB persistence layer (snapshots, stuck `BGSAVE`, restores).
- The FalkorDB §5 *Diagnose and recover a stuck snapshot* covers the
  `THREAD_COUNT` / `OMP_THREAD_COUNT` mitigation that's also a prerequisite
  for stable API behaviour: when the database itself stalls on long Cypher
  queries, the API will appear to hang or time out even though it is
  innocent.
