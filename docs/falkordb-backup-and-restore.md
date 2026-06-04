# FalkorDB backup and restore

This guide explains how SBOM-Graph's FalkorDB instance persists data, how to
trigger snapshots on demand, how to monitor and recover stuck snapshots, how to
export a snapshot off the cluster, how to keep an on-PVC rolling backup set,
and how to restore from one.

If the symptom you're investigating is the **`sbom-graph-api` container
crashing or restarting** (especially while serving `/reports/vulnerabilities`
or other report endpoints), see
[`sbom-graph-api-troubleshooting.md`](./sbom-graph-api-troubleshooting.md) —
that's the API process, not the persistence layer.

Audience: cluster operators / admins running the `sbom-graph` Helm release.

Tested namespace in examples: `sbom-graph`. Substitute your own if different.

---

## Table of contents

1. [How persistence works](#1-how-persistence-works)
2. [Find the FalkorDB pod](#2-find-the-falkordb-pod)
3. [Trigger a snapshot manually](#3-trigger-a-snapshot-manually)
4. [Monitor an in-progress snapshot](#4-monitor-an-in-progress-snapshot)
5. [Diagnose and recover a stuck snapshot](#5-diagnose-and-recover-a-stuck-snapshot)
6. [Backup naming convention](#6-backup-naming-convention)
7. [Create a backup](#7-create-a-backup)
8. [Verify a backup file](#8-verify-a-backup-file)
9. [Why is my backup a different size than last time?](#9-why-is-my-backup-a-different-size-than-last-time)
10. [List and prune backups](#10-list-and-prune-backups)
11. [PVC-level recovery (pod is down)](#11-pvc-level-recovery-pod-is-down)
12. [Restore from a backup](#12-restore-from-a-backup)
13. [Recommended cadence](#13-recommended-cadence)
14. [Reference](#14-reference)

---

## 1. How persistence works

FalkorDB is Redis under the hood, and the only persistence mechanism configured
in this chart is **RDB snapshots** — AOF is disabled. The single committed
snapshot lives at `/data/dump.rdb` inside the FalkorDB pod, on a
`ReadWriteOnce` PVC named after the release (default: `sbom-graph-falkordb`).

The relevant settings live in `helm/charts/sbom-graph/values.yaml` under
`falkordb.server.*` and are passed through to `redis-server` in
`helm/charts/sbom-graph/templates/falkordb-deployment.yaml`.

### 1.1 Automatic snapshot schedule

The schedule is the standard Redis `save "<seconds> <changes> ..."` directive.
The current configuration is:

```yaml
falkordb:
  server:
    save: "900 1 300 100 60 10000"
```

That translates to: trigger a `BGSAVE` if **any one** of these conditions
becomes true.

| Window | Min changed keys | Plain English |
|---|---|---|
| 900 s (15 min) | 1 | At least one key changed in the last 15 minutes |
| 300 s (5 min)  | 100 | At least 100 keys changed in the last 5 minutes |
| 60 s (1 min)   | 10 000 | At least 10 000 keys changed in the last minute |

Redis re-evaluates every ~1 s; the smallest-window threshold that's met wins.

Practical effect:

- During heavy SBOM ingest you'll see a snapshot roughly every minute.
- On an idle cluster you'll see one snapshot every 15 minutes.
- A failed `BGSAVE` does **not** freeze writes — `stop-writes-on-bgsave-error`
  is set to `no` deliberately so a snapshot problem cannot stall the API.
- Because AOF is off, **the only durable copy of the graph is `dump.rdb`**.
  Anything written after the last successful snapshot is lost on an ungraceful
  shutdown (OOMKill, `kubectl delete pod --force`, node failure).

### 1.2 Other events that produce a snapshot

Independent of the schedule, an RDB write also happens on:

- Graceful `SHUTDOWN` — the entrypoint runs an implicit `SAVE` before exit, so
  a normal `kubectl rollout restart` or `helm upgrade` is safe.
- An explicit `BGSAVE` or `SAVE` command (see [§3](#3-trigger-a-snapshot-manually)).
- `DEBUG RELOAD` / `DEBUG SDSLEN`.
- Replica full resync — not used (single-instance, no replicas).

A **kernel OOM kill, `--force` delete, or liveness-probe kill bypasses the
graceful path** and you lose everything since the last successful snapshot.
This is the failure mode the OOMKill-loop incident in May exposed; the current
`maxmemory 3gb` + `noeviction` + 4 GiB cgroup limit combination is sized to
keep that from happening, but it's still the reason to run regular off-cluster
backups.

### 1.3 mTLS

The chart enables TLS with client-cert verification by default
(`falkordb.tls.enabled=true`, `falkordb.tls.requireClientAuth=true`). Every
`redis-cli` invocation inside the pod must include:

```text
--tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key
-h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD"
```

`FALKORDB_PASSWORD` is already in the FalkorDB container's environment; the
TLS material is mounted at `/tls/`. Both are referenced as-is in every command
below.

---

## 2. Find the FalkorDB pod

Use the component label rather than the release-derived pod name so the
commands work regardless of release name:

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')
echo "$FDB_POD"
```

If the deployment is scaled to zero or the pod is `CrashLoopBackOff`, jump
straight to [§11](#11-pvc-level-recovery-pod-is-down).

---

## 3. Trigger a snapshot manually

`BGSAVE` is non-blocking — it forks a child that writes `dump.rdb` while the
main process keeps serving traffic. `LASTSAVE` returns the unix timestamp of
the most recent **successful** snapshot, so polling it past your start time is
the safe completion check.

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"
  before=$(date +%s)
  $RCLI BGSAVE
  while :; do
    last=$($RCLI LASTSAVE)
    [ "$last" -ge "$before" ] && { echo "BGSAVE complete at $last"; break; }
    sleep 2
  done
  ls -lh /data/dump.rdb
'
```

Do **not** use synchronous `SAVE` on a multi-GB graph — it blocks every client
for the full duration of the write.

If the loop never exits within a reasonable time for your dataset (see
[§4.3](#43-expected-durations)), the save is stuck. Go to
[§5](#5-diagnose-and-recover-a-stuck-snapshot).

---

## 4. Monitor an in-progress snapshot

Three sources of ground truth, in decreasing order of trust: Redis's own
`INFO persistence`, the on-disk temp file, the OS process table inside the
pod.

### 4.1 One-shot status check

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  echo "=== Redis persistence state ==="
  $RCLI INFO persistence | grep -E \
    "rdb_bgsave_in_progress|rdb_current_bgsave_time_sec|rdb_last_save_time|rdb_last_bgsave_status|rdb_last_bgsave_time_sec|rdb_changes_since_last_save"

  echo
  echo "=== fork() cost (microseconds) ==="
  $RCLI INFO stats | grep -E "latest_fork_usec|total_forks"

  echo
  echo "=== Files in /data ==="
  ls -lh /data | grep -E "dump\.rdb|temp-.*\.rdb" || echo "  (no rdb files yet)"
'
```

Field meanings:

| Field | Meaning | Healthy value |
|---|---|---|
| `rdb_bgsave_in_progress` | `1` while a BGSAVE child is alive; `0` between saves | Either is fine; `1` means a save is currently running |
| `rdb_current_bgsave_time_sec` | Seconds the **current** BGSAVE has been running. Only meaningful when `_in_progress=1`. | < `rdb_last_bgsave_time_sec` × 1.5 |
| `rdb_last_bgsave_status` | `ok` or `err` for the most recent completed save | `ok` |
| `rdb_last_bgsave_time_sec` | How long the **last completed** BGSAVE took. Your baseline. | Depends on data size; see §4.3 |
| `rdb_last_save_time` | Unix timestamp of last successful save (== `LASTSAVE`) | `date -u -r $value` to read it |
| `rdb_changes_since_last_save` | Keys mutated since last successful save | Grows during ingest, resets to 0 after each save |
| `latest_fork_usec` | Microseconds the most recent `fork()` took. The fork briefly pauses the main thread — the only point at which BGSAVE blocks clients. | < 500 000 µs (0.5 s) is fine; > 2 000 000 µs (2 s) means CoW page-table copy is hurting |
| `total_forks` | Lifetime fork count. Compare to recent BGSAVE log entries to see if Redis is forking but not finishing. | Should match the number of completed `rdb_last_save_time` transitions |

Quick decision tree:

- `rdb_bgsave_in_progress:0` → no save running. The last one finished
  `(now - rdb_last_save_time)` seconds ago.
- `rdb_bgsave_in_progress:1` and `rdb_current_bgsave_time_sec` <
  `rdb_last_bgsave_time_sec × 2` → normal, in progress.
- `rdb_bgsave_in_progress:1` and `rdb_current_bgsave_time_sec` >>>
  `rdb_last_bgsave_time_sec` → suspicious, jump to
  [§5](#5-diagnose-and-recover-a-stuck-snapshot).
- `rdb_last_bgsave_status:err` → previous BGSAVE failed; check FalkorDB pod
  logs for "Background saving error" / "fork: Cannot allocate memory" / OOM.

### 4.2 Live watch

The committed file is `/data/dump.rdb`. While a BGSAVE runs, the child writes
to `/data/temp-<child-pid>.rdb` and atomically renames it on completion.
Watching that temp file is the most honest "is it actually doing work?" check
because it bypasses Redis's own reporting.

```bash
kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  while :; do
    in_progress=$($RCLI INFO persistence | awk -F: "/rdb_bgsave_in_progress:/ {gsub(/\r/,\"\"); print \$2}")
    cur_sec=$($RCLI INFO persistence | awk -F: "/rdb_current_bgsave_time_sec:/ {gsub(/\r/,\"\"); print \$2}")
    last_size=$(ls -l /data/dump.rdb 2>/dev/null | awk "{print \$5}")
    temp_info=$(ls -l /data/temp-*.rdb 2>/dev/null | awk "{printf \"%s (%s bytes)\", \$NF, \$5}")
    printf "%s  in_progress=%s  current_sec=%s  dump.rdb=%s  temp=%s\n" \
      "$(date -u +%H:%M:%S)" "${in_progress:-?}" "${cur_sec:-0}" "${last_size:-?}" "${temp_info:-none}"
    [ "$in_progress" = "0" ] && [ "${cur_sec:-0}" = "0" ] && break
    sleep 2
  done
'
```

What a healthy save looks like:

- `in_progress=1` from the moment `BGSAVE` returns.
- `current_sec` increments by ~2 each line.
- `temp` is present and its byte count grows monotonically.
- When it finishes: `temp` disappears, `dump.rdb` jumps to (approximately) the
  final temp size, `in_progress=0`.

What "stuck" looks like:

- `in_progress=1`, `current_sec` keeps climbing, **temp file byte size does
  not grow** — the child is alive but not writing. Usually disk-pressure or a
  stalled `write()` on hostpath under heavy host I/O.
- `in_progress=1` but **no temp file at all** — the fork didn't produce a
  writer; if it persists more than a few seconds it points to fork failure
  (Redis log will show `fork: Cannot allocate memory`). Cgroup memory limit
  is the usual cause — the child needs at least the parent's RSS in CoW
  headroom.
- `current_sec` jumps to 0 multiple times → the child was killed and Redis is
  auto-retrying. Match against `rdb_last_bgsave_status:err`.

### 4.3 Expected durations

Rough order-of-magnitude reference for this deployment (single FalkorDB pod,
4 GiB cgroup limit, hostpath PVC inside minikube/podman):

| RSS at fork | Fork time | BGSAVE wall time |
|---|---|---|
| ~50 MB | < 5 ms | < 1 s |
| ~500 MB | 5–50 ms | 1–5 s |
| ~2 GB | 50–200 ms | 10–60 s |
| ~4 GB | 200 ms – 2 s | 30–120 s |

On a real cluster with proper block storage these numbers improve roughly
2–4×. If you see fork times > 2 s or write throughput < 10 MB/s into the temp
file, the bottleneck is your minikube/podman VM under host pressure — `uptime`
on the host machine often shows the smoking gun (load average 40+ during the
May 28 incident is what krunkit thrash looks like).

---

## 5. Diagnose and recover a stuck snapshot

If `rdb_current_bgsave_time_sec` is in the thousands and the temp file is
zero-sized or unchanged across multiple checks, the BGSAVE is wedged.

### 5.1 Three-source diagnostic

Run this — it confirms the state and identifies the wedged child by PID.

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  echo "==== $(date -u +%H:%M:%S) ===="
  $RCLI INFO persistence | grep -E "rdb_bgsave_in_progress|rdb_current_bgsave_time_sec|rdb_last_bgsave_status|rdb_last_save_time"
  echo
  ls -l /data/temp-*.rdb 2>/dev/null || echo "no temp file"
  echo
  parent=$(pidof redis-server 2>/dev/null | tr " " "\n" | sort -n | head -1)
  echo "parent redis-server PID: ${parent:-?}"

  # The temp file name encodes the child PID: temp-<pid>.rdb
  for f in /data/temp-*.rdb; do
    [ -f "$f" ] || continue
    pid=$(basename "$f" .rdb | sed "s/^temp-//")
    if [ -d "/proc/$pid" ]; then
      state=$(awk "/^State:/ {print \$2,\$3}" "/proc/$pid/status")
      threads=$(ls "/proc/$pid/task" 2>/dev/null | wc -l)
      fds=$(ls -l "/proc/$pid/fd" 2>/dev/null | grep -E "temp-|/data/" | wc -l)
      echo "  candidate child PID $pid: state=$state threads=$threads data-fds=$fds"
    else
      echo "  temp file $f references PID $pid - process is GONE (orphaned)"
    fi
  done
'
```

The temp filename convention `temp-<pid>.rdb` tells you which PID was the
writer. The block above prints, for each temp file, whether that PID is still
alive in `/proc`, its current task state, thread count, and how many file
descriptors it has open on `/data/`.

### 5.2 Process state guide

| State | Meaning | What it tells you |
|---|---|---|
| `R` (running) | On-CPU now | Should be making progress; if temp file isn't growing, see fd count |
| `S` (interruptible sleep) | Waiting on a condition / futex / I/O completion | If temp size is 0 and stays 0, almost certainly a userspace lock deadlock — see §5.4 |
| `D` (uninterruptible sleep) | Stuck in a kernel syscall (typically disk I/O) | Storage / VM problem — host load is the usual culprit |
| `Z` (zombie) | Exited, not yet reaped by parent | Parent has lost track of it; will need `BGSAVE CANCEL` or pod restart |
| missing from `/proc` | Already died | Redis has lost the SIGCHLD; flag will not clear without help |

A note on `/proc/<pid>/wchan`: on Linux kernels ≥ 5.15 (which includes the
minikube VMs used here) this field returns `0` to non-privileged readers as
a hardening measure. **A `wchan` of `0` does not mean "free-running"** — it
just means the kernel is hiding the kernel function the process is blocked
in. Use the `State:` field instead.

### 5.3 Recovery flow

Try in order. Each step is non-destructive of the last good `dump.rdb`.

**Step 1 — graceful cancel** (Redis 7.4+):

```bash
kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" BGSAVE CANCEL

  sleep 3
  redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" INFO persistence \
    | grep -E "rdb_bgsave_in_progress|rdb_last_bgsave_status"
'
```

You want `rdb_bgsave_in_progress:0`. If `BGSAVE CANCEL` returns
`ERR unknown subcommand` (older Redis core) or the flag stays at `1`, go to
step 2.

**Step 2 — kill the child directly** (works whatever its state, including
`S` and `D`):

```bash
# Replace 55514 with the PID identified in §5.1
CHILD_PID=55514

kubectl -n "$NS" exec "$FDB_POD" -- sh -c "
  if [ -d /proc/${CHILD_PID} ]; then
    kill -9 ${CHILD_PID} && echo 'SIGKILL sent to ${CHILD_PID}'
  else
    echo 'PID ${CHILD_PID} already gone - parent has not reaped'
  fi
  sleep 2
  redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a \"\$FALKORDB_PASSWORD\" INFO persistence \
    | grep -E 'rdb_bgsave_in_progress|rdb_last_bgsave_status'
"
```

If the flag clears, jump to step 4 (verify).

**Step 3 — pod restart** (universal hammer; needed when the child already
died but the parent didn't notice, leaving an unclearable in-progress flag):

```bash
kubectl -n "$NS" rollout restart deploy/sbom-graph-falkordb
kubectl -n "$NS" rollout status deploy/sbom-graph-falkordb --timeout=180s
```

Safe: `dump.rdb` on disk is your last good snapshot and FalkorDB will reload
from it on boot. The cost is whatever was written since `rdb_last_save_time`.
After the new pod is ready, force every client to rebuild its connection pool
(stale pools cause spurious "connection refused" errors against the new pod):

```bash
# Restart every FalkorDB client by component label.  Works regardless of
# Helm release name.
kubectl -n "$NS" rollout restart deploy \
  -l 'app.kubernetes.io/component in (sbom-graph-api,enrichment,enrichment-beat,sonatype-lifecycle-release-listener)'
```

If you prefer named restarts for a default `sbom-graph` release, the
actual deployment names produced by the chart are:

```bash
kubectl -n "$NS" rollout restart deploy/sbom-graph-sbom-graph-api
kubectl -n "$NS" rollout restart deploy/sbom-graph-enrichment             # worker (no -worker suffix)
kubectl -n "$NS" rollout restart deploy/sbom-graph-enrichment-beat
kubectl -n "$NS" rollout restart deploy/sbom-graph-sonatype-lifecycle-release-listener
```

(Run `kubectl -n "$NS" get deploy -L app.kubernetes.io/component` if you
need to confirm the exact names in your cluster.)

**Step 4 — verify and clean up orphaned temp files**:

```bash
kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  echo "=== state after intervention ==="
  $RCLI INFO persistence | grep -E "rdb_bgsave_in_progress|rdb_last_bgsave_status|rdb_last_save_time"

  echo
  echo "=== trigger a fresh BGSAVE ==="
  before=$(date +%s)
  $RCLI BGSAVE
  for i in $(seq 1 60); do
    last=$($RCLI LASTSAVE)
    [ "$last" -ge "$before" ] && { echo "completed in $((last - before)) s"; break; }
    sleep 2
  done

  echo
  echo "=== clean up orphans ==="
  rm -v /data/temp-*.rdb 2>/dev/null || echo "  nothing to remove"
  ls -lh /data/dump.rdb
'
```

If the fresh save also wedges at 0 bytes the failure is reproducible, not a
fluke — see [§5.5](#55-mitigation).

**Step 5 — lock in an off-cluster backup immediately**. Once `INFO persistence`
shows a clean `rdb_last_bgsave_status:ok` and the new `dump.rdb` is on disk,
pull a copy off the cluster *before* doing anything else. This is the moment
the data is provably good and the database is provably healthy; if a second
wedge happens within the next save window you still have a known-good
artefact to restore from.

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')
ts=$(date -u +%Y%m%dT%H%M%S)

kubectl -n "$NS" exec "$FDB_POD" -- \
  tar cf - -C /data dump.rdb | tar xf - -O > "./dump-${ts}.rdb"

# Quick integrity check — see §8.
head -c 9 "./dump-${ts}.rdb" | od -c | head -1
ls -lh "./dump-${ts}.rdb"
```

You should see `R E D I S 0 0 N N` and a non-zero file size that matches
`/data/dump.rdb` inside the pod. Push the file to long-term storage before
moving on to [§5.5](#55-mitigation) to address the underlying cause.

### 5.4 Why it happens

Three known causes in this deployment, ranked by historical frequency.

**A. Module / fork interaction (most common)**. FalkorDB carries GraphBLAS
with internal locking. Linux `fork()` clones only the calling thread, but it
clones **the entire memory image including held mutex state**. If a non-main
parent thread held an internal mutex at the instant of `fork()`, the child
inherits a "locked" mutex whose owner doesn't exist in the child. The first
acquisition attempt then blocks forever in a futex wait. Symptom matches
exactly: child is single-threaded, state `S`, temp file 0 bytes, no fds on
`/data/`. Mitigation in [§5.5](#55-mitigation).

**B. Host VM I/O thrash**. On minikube/podman, `krunkit` or
`qemu-system-x86_64` can saturate the host CPU and starve the VM's I/O path.
The BGSAVE child enters state `D` on a kernel write and stays there. Symptom:
child in state `D`, temp file present but byte count not changing, `uptime`
on the host shows load average > 10 with `krunkit` or `qemu-system-x86_64`
at hundreds of percent CPU. Killing the child gives back the save slot but
will recur every 15 minutes until the host VM is recovered.

**C. Cgroup memory exhaustion at fork**. If the parent's RSS approaches the
4 GiB limit, the kernel may refuse `fork()` with `Cannot allocate memory`.
Symptom: `rdb_last_bgsave_status:err`, log line `Can't save in background:
fork: Cannot allocate memory`, no child exists. Fix by raising the cgroup
limit (`falkordb.resources.limits.memory` in `values.yaml`).

### 5.5 Mitigation

For **case A** (the FalkorDB fork-deadlock pattern), drop the module's
worker-thread count so any held lock is owned by the main thread at fork
time. Two ways:

- **Runtime, immediate effect** — no restart required, no chart change:

  ```bash
  kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
    redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
      -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" GRAPH.CONFIG SET THREAD_COUNT 1
    redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
      -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" GRAPH.CONFIG SET OMP_THREAD_COUNT 1
  '
  ```

  This costs query parallelism but eliminates fork-time lock contention for
  small/medium graphs. Reverts on pod restart.

- **Persistent via chart** — already wired into this chart as the default.
  `helm/charts/sbom-graph/values.yaml` exposes a knob under
  `falkordb.server.module`, and the deployment template appends those values
  to the `--loadmodule` line so they take effect from the very first
  `BGSAVE` after the pod starts:

  ```yaml
  falkordb:
    server:
      module:
        threadCount: "1"      # default — drop the fork-deadlock hazard
        ompThreadCount: "1"   # default — drop the fork-deadlock hazard
  ```

  No edit required; just `helm upgrade` to roll the running pod onto the
  module args. To verify after the rollout:

  ```bash
  kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
    redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
      -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" GRAPH.CONFIG GET THREAD_COUNT
    redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
      -h 127.0.0.1 -p 6379 -a "$FALKORDB_PASSWORD" GRAPH.CONFIG GET OMP_THREAD_COUNT
  '
  # Expect:  THREAD_COUNT       1
  #          OMP_THREAD_COUNT   1
  ```

  To **disable** the override (e.g. once the upstream FalkorDB fork-safety
  fix lands in your image tag), set either value to the empty string in your
  values override — the template emits nothing for empty values, so FalkorDB
  falls back to its CPU-count auto-detection:

  ```yaml
  falkordb:
    server:
      module:
        threadCount: ""
        ompThreadCount: ""
  ```

For **case B** (host VM thrash), the cluster cannot fix it from inside —
check the host with `uptime` and `ps -A o %cpu,rss,comm | sort -rn | head -8`
and clean up. A clean `podman machine stop && podman machine start` followed
by `minikube start` is the reliable recovery; expect ~5–10 minutes.

For **case C**, raise `falkordb.resources.limits.memory` in `values.yaml` and
`helm upgrade`. The pod's existing data survives the upgrade.

---

## 6. Backup naming convention

The cleanup script and the procedures below assume a single, predictable
location and filename pattern for on-PVC backup copies:

| Property | Value |
|---|---|
| Directory | `/data/backups/` (inside the FalkorDB pod / PVC) |
| Filename | `dump-YYYYMMDDTHHMMSS.rdb` |
| Example | `/data/backups/dump-20260529T142301.rdb` |

The cleanup script (`scripts/falkordb-cleanup-backups.sh`) only touches files
matching `dump-*.rdb` under `/data/backups/`. The live committed snapshot
(`/data/dump.rdb`) and any in-progress `temp-*.rdb` files Redis itself writes
during a `BGSAVE` are never touched by the script.

---

## 7. Create a backup

Two flavours: on-PVC (cheap, fast, retained on the cluster) and off-cluster
(pull a copy to your machine or to long-term storage).

### 7.1 On-PVC backup copy

Trigger a fresh snapshot, then copy `dump.rdb` into `/data/backups/` with a
timestamped name. The copy is local to the same volume so it's near-instant
even for multi-GB files.

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  set -e
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  before=$(date +%s)
  $RCLI BGSAVE
  while :; do
    last=$($RCLI LASTSAVE)
    [ "$last" -ge "$before" ] && break
    sleep 2
  done

  mkdir -p /data/backups
  ts=$(date -u +%Y%m%dT%H%M%S)
  dst=/data/backups/dump-${ts}.rdb
  cp /data/dump.rdb "$dst"
  ls -lh "$dst"
'
```

Run this from a cron job, a CI pipeline, or by hand. Pair it with
`scripts/falkordb-cleanup-backups.sh` to keep the directory bounded.

### 7.2 Off-cluster export

Pick the form that fits the environment.

**Option A — `kubectl cp` (simplest)**:

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

# (Optional) trigger a fresh BGSAVE first - see §3.

ts=$(date -u +%Y%m%dT%H%M%S)
kubectl -n "$NS" cp \
  "$FDB_POD:/data/dump.rdb" \
  "./dump-${ts}.rdb"
```

You will see this on stderr:

```text
tar: Removing leading `/' from member names
```

This is a **harmless GNU tar warning**, not an error. `kubectl cp` is `tar`
over the exec channel and GNU tar refuses to put absolute paths into archive
members. The file is still copied correctly — verify with
[§8](#8-verify-a-backup-file).

**Option B — pipe `tar` directly** (avoids the warning, slightly faster
because there's one tar pass instead of two):

```bash
ts=$(date -u +%Y%m%dT%H%M%S)
kubectl -n "$NS" exec "$FDB_POD" -- \
  tar cf - -C /data dump.rdb | tar xf - -O > "./dump-${ts}.rdb"
```

Using `-C /data dump.rdb` (relative path) inside the pod means there's no
leading `/` to strip, so no warning.

**Option C — filter just the warning** (keeps real errors visible):

```bash
kubectl -n "$NS" cp "$FDB_POD:/data/dump.rdb" "./dump-${ts}.rdb" \
  2> >(grep -v "tar: Removing leading" >&2)
```

Notes that apply to all three:

- The copy streams via the exec channel — no Redis credentials needed, and
  the size of the file is not a memory pressure on the pod.
- For automation, push the resulting file straight to object storage; do not
  leave production graph dumps lying around on workstations.

### 7.3 Minikube hostpath shortcut

On minikube the `standard` storage class is a hostpath provisioner. When the
API server is wedged but the VM is up, you can read the file directly:

```bash
NS=sbom-graph
PV_NAME=$(kubectl -n "$NS" get pvc \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].spec.volumeName}')
HOST_PATH=$(kubectl get pv "$PV_NAME" -o jsonpath='{.spec.hostPath.path}')

minikube ssh "sudo cat ${HOST_PATH}/dump.rdb" > "./dump-$(date -u +%Y%m%dT%H%M%S).rdb"
```

If `minikube ssh` itself fails (we've seen this when the krunkit / podman VM
saturates), fall back to PVC-level recovery in
[§11](#11-pvc-level-recovery-pod-is-down).

---

## 8. Verify a backup file

Two quick checks for every exported file, one deep check when stakes are
high.

### 8.1 Magic bytes

A valid RDB starts with the ASCII bytes `REDIS` followed by a 4-digit version
number, e.g. `REDIS0011`:

```bash
ts=YOUR_TIMESTAMP
head -c 9 "./dump-${ts}.rdb" | od -c | head -1
```

You should see `R   E   D   I   S   0   0   1   1` (or similar 4-digit
version). Anything else means the file is truncated, corrupted, or not an
RDB.

### 8.2 Size sanity

The exported file should be within a few bytes of `dump.rdb` inside the pod
at the time of export. A 0-byte or unusually small file means a stuck
BGSAVE was copied out:

```bash
ls -lh "./dump-${ts}.rdb"
kubectl -n "$NS" exec "$FDB_POD" -- ls -l /data/dump.rdb
```

For why the size can legitimately change between exports, see
[§9](#9-why-is-my-backup-a-different-size-than-last-time).

### 8.3 Full structural verification

The Redis container ships `redis-check-rdb`, which walks the entire file and
validates the CRC64 checksum (RDB checksums are on:
`falkordb.server.rdbChecksum: "yes"`):

```bash
docker run --rm -v "$PWD:/work" -w /work redis:7 \
  redis-check-rdb "dump-${ts}.rdb"
```

A successful run exits 0 and prints `\o/ RDB looks OK \o/`. Run this before
relying on a backup for restore.

---

## 9. Why is my backup a different size than last time?

`dump.rdb` snapshots the **entire Redis instance**, not just the graph. In
this deployment four very different things share that file:

| DB | Owner | What it stores                                                      |
|---|---|---------------------------------------------------------------------|
| 0 | FalkorDB module | The `acme-corp` graph (`falkordb.server` keys + GraphBLAS matrices) |
| 1 | Celery broker | Pending task messages (queues like `celery`, `enrichment`, …)       |
| 2 | Celery result backend | Per-task result records with their JSON payloads (often with a TTL) |
| 0 | Other | Trust-score caches, beat schedules, etc.                            |

The `celeryBrokerDb: "1"` / `celeryResultDb: "2"` values in
`helm/charts/sbom-graph/values.yaml` confirm this. The total snapshot size
swings between exports for three legitimate reasons:

1. **Celery backlog drains**. Result records have a TTL (default 1 day),
   which alone can swing the file size by hundreds of MB between snapshots
   on a busy system. Big retry storms (e.g. after a FalkorDB recovery)
   temporarily inflate DB 1.
2. **Ingest activity**. Heavy CycloneDX ingestion fills DB 0 with new
   Version/Project nodes and edges.
3. **Refresh jobs**. Centrality and trust-score recomputes write large
   intermediate sets into the graph.

To check where the bytes are right now, run this diagnostic in the pod:

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  RCLI="redis-cli --tls \
    --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
    -h 127.0.0.1 -p 6379 -a $FALKORDB_PASSWORD"

  echo "=== Memory ==="
  $RCLI INFO memory | grep -E "used_memory_human|used_memory_rss_human|maxmemory_human"

  echo
  echo "=== Keyspace per DB ==="
  $RCLI INFO keyspace

  echo
  echo "=== Graph object size (DB 0) ==="
  $RCLI -n 0 GRAPH.QUERY acme-corp "MATCH (n) RETURN count(n) AS nodes"
  $RCLI -n 0 GRAPH.QUERY acme-corp "MATCH ()-[r]->() RETURN count(r) AS edges"
  $RCLI -n 0 MEMORY USAGE acme-corp

  echo
  echo "=== Celery broker (DB 1) queue depths ==="
  for q in celery enrichment centrality trust_score; do
    n=$($RCLI -n 1 LLEN "$q" 2>/dev/null || echo "n/a")
    printf "  %-20s LLEN=%s\n" "$q" "$n"
  done

  echo
  echo "=== Celery results (DB 2) count + sample TTL ==="
  $RCLI -n 2 DBSIZE
  sample=$($RCLI -n 2 RANDOMKEY)
  if [ -n "$sample" ]; then
    ttl=$($RCLI -n 2 TTL "$sample")
    bytes=$($RCLI -n 2 STRLEN "$sample" 2>/dev/null || echo "n/a")
    echo "  sample key:  $sample"
    echo "  sample TTL:  ${ttl}s"
    echo "  sample size: $bytes bytes"
  fi
'
```

What the output tells you:

- The `db0 / db1 / db2` keyspace ratio shows whose data dominates today.
- `MEMORY USAGE acme-corp` is the live in-memory size of just the graph
  object. If that's close to the file size, the file is fundamentally
  graph-sized and any historical 10× delta was Celery state.
- Compare `MATCH (n) RETURN count(n)` to a previous backup window. The graph
  is the persistent business data; everything else is operational state.
- `db1` `LLEN` near zero means the worker has drained its backlog. `db2
  DBSIZE` will drop sharply over the first 24 h after a backlog clears
  (Celery `result_expires` default).

When to be alarmed: **only** if DB 0's graph counts are smaller than the
previous backup with no corresponding ingest / delete activity. Otherwise
size differences are normal operational noise.

---

## 10. List and prune backups

### 10.1 List

```bash
NS=sbom-graph
FDB_POD=$(kubectl -n "$NS" get pod \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

kubectl -n "$NS" exec "$FDB_POD" -- sh -c '
  ls -lh /data/backups/ 2>/dev/null || echo "no backups yet"
'
```

### 10.2 Prune with the cleanup script

`scripts/falkordb-cleanup-backups.sh` runs **from outside the cluster** (on
your workstation, CI runner, cron host, …) but executes its actual `rm`
commands **inside the FalkorDB pod** via `kubectl exec`. Nothing is downloaded
or buffered locally.

Basic usage — keep the newest 7 backups:

```bash
./scripts/falkordb-cleanup-backups.sh
```

Common flags:

```bash
./scripts/falkordb-cleanup-backups.sh --retain 14            # keep newest 14
./scripts/falkordb-cleanup-backups.sh --namespace prod-sbg   # target a different namespace
./scripts/falkordb-cleanup-backups.sh --dry-run              # preview only
./scripts/falkordb-cleanup-backups.sh --backup-dir /data/backups
./scripts/falkordb-cleanup-backups.sh --help
```

Behaviour:

- Selects the FalkorDB pod by `app.kubernetes.io/component=falkordb`.
- Considers only files matching `dump-*.rdb` directly under the backup
  directory. Subdirectories, the live `dump.rdb`, and any `temp-*.rdb` are
  always ignored.
- Sorts by modification time (newest first), keeps the top `--retain`, deletes
  the rest.
- Refuses to run with `--retain 0` so an off-by-one in automation can never
  wipe every backup.
- Refuses backup directories outside `/data/` (defence in depth against typos
  like `--backup-dir /`).
- Exits non-zero on any error.

Schedule it from a CronJob, GitOps periodic task, or your laptop's `cron` —
all it needs is `kubectl` configured for the target cluster.

---

## 11. PVC-level recovery (pod is down)

If FalkorDB won't stay up (crash loop, OOMKill, corrupted RDB) you cannot use
`kubectl exec` or `redis-cli`. Mount the PVC into a throwaway pod instead.
The PVC is `ReadWriteOnce`, so you must first scale FalkorDB to zero.

```bash
NS=sbom-graph
PVC=$(kubectl -n "$NS" get pvc \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

# Free the RWO PVC.
kubectl -n "$NS" scale deploy/sbom-graph-falkordb --replicas=0

cat <<EOF | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: falkordb-recovery
spec:
  restartPolicy: Never
  containers:
    - name: shell
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      volumeMounts:
        - name: data
          mountPath: /data
          readOnly: true
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: ${PVC}
        readOnly: true
EOF

kubectl -n "$NS" wait --for=condition=Ready pod/falkordb-recovery --timeout=60s
kubectl -n "$NS" exec falkordb-recovery -- ls -lh /data /data/backups

# Pull off whichever file is still good.
kubectl -n "$NS" cp falkordb-recovery:/data/dump.rdb ./dump-recovered.rdb

# Clean up and put FalkorDB back.
kubectl -n "$NS" delete pod falkordb-recovery
kubectl -n "$NS" scale deploy/sbom-graph-falkordb --replicas=1
```

If `/data/dump.rdb` itself is corrupt, copy out the most recent
`/data/backups/dump-*.rdb` instead and restore from it (next section).

---

## 12. Restore from a backup

There is no in-Redis "restore" command; the runtime reads `dump.rdb` once at
startup. So the restore procedure is: stop the database, replace
`/data/dump.rdb` with the backup, start the database.

```bash
NS=sbom-graph
BACKUP=dump-20260529T142301.rdb     # adjust

# 1. Scale down so the RWO PVC is free and no writer is active.
kubectl -n "$NS" scale deploy/sbom-graph-falkordb --replicas=0
kubectl -n "$NS" wait --for=delete pod \
  -l app.kubernetes.io/component=falkordb --timeout=120s

# 2. Spin up a writer pod against the PVC.
PVC=$(kubectl -n "$NS" get pvc \
  -l app.kubernetes.io/component=falkordb \
  -o jsonpath='{.items[0].metadata.name}')

cat <<EOF | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: falkordb-restore
spec:
  restartPolicy: Never
  containers:
    - name: shell
      image: busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: ${PVC}
EOF
kubectl -n "$NS" wait --for=condition=Ready pod/falkordb-restore --timeout=60s

# 3. Verify the backup file exists and replace dump.rdb atomically.
kubectl -n "$NS" exec falkordb-restore -- sh -c "
  set -e
  test -f /data/backups/${BACKUP} || { echo 'backup missing'; exit 1; }
  cp /data/dump.rdb /data/dump.rdb.pre-restore 2>/dev/null || true
  cp /data/backups/${BACKUP} /data/dump.rdb.new
  mv /data/dump.rdb.new /data/dump.rdb
  ls -lh /data/dump.rdb /data/dump.rdb.pre-restore 2>/dev/null
"

# 4. Tear down the writer pod and bring FalkorDB back.
kubectl -n "$NS" delete pod falkordb-restore
kubectl -n "$NS" scale deploy/sbom-graph-falkordb --replicas=1
kubectl -n "$NS" rollout status deploy/sbom-graph-falkordb --timeout=300s
```

After the FalkorDB pod is `1/1 Ready`, force every client to rebuild its
connection pool against the restored backend:

```bash
# Restart every FalkorDB client by component label.  Works regardless of
# Helm release name.
kubectl -n "$NS" rollout restart deploy \
  -l 'app.kubernetes.io/component in (sbom-graph-api,enrichment,enrichment-beat,sonatype-lifecycle-release-listener)'
```

If you prefer named restarts for a default `sbom-graph` release, the
actual deployment names produced by the chart are:

```bash
kubectl -n "$NS" rollout restart deploy/sbom-graph-sbom-graph-api
kubectl -n "$NS" rollout restart deploy/sbom-graph-enrichment             # worker (no -worker suffix)
kubectl -n "$NS" rollout restart deploy/sbom-graph-enrichment-beat
kubectl -n "$NS" rollout restart deploy/sbom-graph-sonatype-lifecycle-release-listener
```

(Run `kubectl -n "$NS" get deploy -L app.kubernetes.io/component` if you
need to confirm the exact names in your cluster.)

---

## 13. Recommended cadence

| Activity | Cadence | Notes |
|---|---|---|
| Automatic `save` snapshots | continuous, per `save "900 1 300 100 60 10000"` | Free — already happening |
| On-PVC backup ([§7.1](#71-on-pvc-backup-copy)) | hourly during ingest, daily otherwise | Cheap, survives pod restart |
| Off-cluster export ([§7.2](#72-off-cluster-export)) | daily, plus before any `helm upgrade` of FalkorDB or the chart | Survives PVC loss |
| `scripts/falkordb-cleanup-backups.sh --retain N` | once per backup cycle | Keep `N` between 7 and 30 depending on disk |
| Backup verification ([§8.3](#83-full-structural-verification)) | on every off-cluster export | Catch silent corruption early |
| Snapshot monitoring ([§4](#4-monitor-an-in-progress-snapshot)) | spot-check after large ingests | Catches stuck BGSAVE while still recoverable |
| Restore drill | quarterly | Time the restore + downstream rollout-restart |

---

## 14. Reference

Source of truth for the schedule and persistence behaviour:

| Setting | File | Default                                    |
|---|---|--------------------------------------------|
| `falkordb.server.save` | `helm/charts/sbom-graph/values.yaml` | `"900 1 300 100 60 10000"`                 |
| `falkordb.server.stopWritesOnBgsaveError` | same | `"no"`                                     |
| `falkordb.server.appendonly` | same | `"no"`                                     |
| `falkordb.server.maxmemory` | same | `"3gb"`                                    |
| `falkordb.server.module.threadCount` | same | `"1"` (fork-deadlock mitigation; see §5.5) |
| `falkordb.server.module.ompThreadCount` | same | `"1"` (fork-deadlock mitigation; see §5.5) |
| `falkordb.persistence.size` | same | `5Gi`                                      |
| `falkordb.tls.requireClientAuth` | same | `true`                                     |
| `enrichment.celeryBrokerDb` | same | `"1"`                                      |
| `enrichment.celeryResultDb` | same | `"2"`                                      |
| `graphName` | same | `"acme-corp"`                              |

Rendered into the running container by:

- `helm/charts/sbom-graph/templates/falkordb-deployment.yaml`
- `helm/charts/sbom-graph/templates/falkordb-pvc.yaml`

Useful Redis reference:

- `INFO persistence`, `INFO memory`, `INFO keyspace`, `INFO stats`
- `BGSAVE`, `BGSAVE CANCEL` (Redis 7.4+), `LASTSAVE`
- `GRAPH.CONFIG GET/SET THREAD_COUNT`, `GRAPH.CONFIG GET/SET OMP_THREAD_COUNT`
- `GRAPH.QUERY <name> "<cypher>"`
- `MEMORY USAGE <key>`
- `redis-check-rdb <file>` (shipped with the `redis:7` Docker image)
