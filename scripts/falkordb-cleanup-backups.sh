#!/usr/bin/env bash
# Prune on-PVC FalkorDB backups, keeping only the newest N.
#
# Runs from outside the cluster: locates the FalkorDB pod via the
# `app.kubernetes.io/component=falkordb` label, then executes the listing /
# deletion entirely inside the pod via `kubectl exec`. No backup data is
# downloaded or buffered locally.
#
# Only files matching `dump-*.rdb` directly under the backup directory are
# considered. The live `dump.rdb`, any in-progress `temp-*.rdb`, and
# subdirectories are always left alone.
#
# Usage:
#   scripts/falkordb-cleanup-backups.sh \
#     [--namespace NS] [--retain N] [--backup-dir DIR] [--dry-run]
#
# Defaults: namespace=sbom-graph, retain=7, backup-dir=/data/backups
#
# Exit codes:
#   0  success (something was deleted, or nothing to do)
#   1  argument / validation error
#   2  could not locate the FalkorDB pod
#   3  in-pod execution failure
#
# See docs/falkordb-backup-and-restore.md for the full backup workflow.

set -euo pipefail

NAMESPACE="sbom-graph"
RETAIN=7
BACKUP_DIR="/data/backups"
DRY_RUN=0
POD_LABEL="app.kubernetes.io/component=falkordb"

usage() {
    cat <<'EOF'
falkordb-cleanup-backups.sh - prune on-PVC FalkorDB backups

Usage:
  scripts/falkordb-cleanup-backups.sh [options]

Options:
  -n, --namespace NS       Kubernetes namespace (default: sbom-graph)
  -r, --retain N           Number of newest backups to keep (default: 7,
                           minimum 1 to prevent accidentally deleting all)
  -d, --backup-dir DIR     Backup directory inside the pod
                           (default: /data/backups, must start with /data/)
      --dry-run            Show what would be deleted, change nothing
  -h, --help               Show this help and exit

The script targets the pod selected by:
  -l app.kubernetes.io/component=falkordb

and considers only files matching `dump-*.rdb` directly under the backup
directory. The committed snapshot at `/data/dump.rdb` is never touched.
EOF
}

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

err() {
    printf '[%s] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--namespace)
            [[ $# -ge 2 ]] || { err "--namespace requires a value"; exit 1; }
            NAMESPACE="$2"
            shift 2
            ;;
        -r|--retain)
            [[ $# -ge 2 ]] || { err "--retain requires a value"; exit 1; }
            RETAIN="$2"
            shift 2
            ;;
        -d|--backup-dir)
            [[ $# -ge 2 ]] || { err "--backup-dir requires a value"; exit 1; }
            BACKUP_DIR="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "Unknown argument: $1"
            usage >&2
            exit 1
            ;;
    esac
done

# Validate inputs before reaching out to the cluster: every value below is
# interpolated into a remote `sh -c` invocation, so a strict allow-list
# keeps shell metacharacters out of the pod (defence in depth on top of the
# fact that we never accept these from anonymous remote callers).

if ! [[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    err "Invalid namespace: $NAMESPACE (must match RFC 1123)"
    exit 1
fi

if ! [[ "$RETAIN" =~ ^[0-9]+$ ]]; then
    err "Invalid --retain value: $RETAIN (must be a non-negative integer)"
    exit 1
fi

if (( RETAIN < 1 )); then
    err "--retain must be at least 1 to avoid deleting every backup"
    exit 1
fi

# Backup dir must live under /data/ so a typo cannot rm somewhere unsafe.
# Disallow `..`, single/double quotes, backticks, $, ;, &, |, newlines.
if [[ "$BACKUP_DIR" != /data/* && "$BACKUP_DIR" != "/data" ]]; then
    err "Invalid --backup-dir: must start with /data/ (got: $BACKUP_DIR)"
    exit 1
fi
if [[ "$BACKUP_DIR" =~ [[:space:]\'\"\`\$\;\&\|]|\.\. ]]; then
    err "Invalid characters in --backup-dir"
    exit 1
fi

# Locate the FalkorDB pod
if ! command -v kubectl >/dev/null 2>&1; then
    err "kubectl not found in PATH"
    exit 1
fi

log "Locating FalkorDB pod in namespace '$NAMESPACE' (label $POD_LABEL)"
FDB_POD=$(kubectl -n "$NAMESPACE" get pod \
    -l "$POD_LABEL" \
    -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' \
    2>/dev/null | awk '{print $1}')

if [[ -z "$FDB_POD" ]]; then
    err "No running FalkorDB pod found in namespace '$NAMESPACE'."
    err "Hint: kubectl -n $NAMESPACE get pods -l $POD_LABEL"
    exit 2
fi

log "Using pod: $FDB_POD"
log "Backup directory: $BACKUP_DIR"
log "Retention: keep newest $RETAIN backup(s)"
if (( DRY_RUN == 1 )); then
    log "Mode: DRY RUN (no files will be deleted)"
fi

# Build the remote command. Values are interpolated as positional args via
# `sh -c '...' _ "$1" "$2" "$3"` style so the remote shell receives them as
# arguments, not embedded text - this is the parameterised-command equivalent
# of the shell-injection-safe approach we apply to database queries.
REMOTE_SCRIPT=$(cat <<'REMOTE'
set -eu

BACKUP_DIR="$1"
RETAIN="$2"
DRY_RUN="$3"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "no-backup-dir"
    exit 0
fi

# List candidates: regular files directly under $BACKUP_DIR matching
# dump-*.rdb, sorted by mtime newest-first. `ls -1t` works on both GNU
# coreutils and BusyBox.
cd "$BACKUP_DIR"

# shellcheck disable=SC2012  # we want ls's -t ordering, not find+sort
files=$(ls -1t 2>/dev/null | while IFS= read -r f; do
    case "$f" in
        dump-*.rdb)
            [ -f "$f" ] && printf '%s\n' "$f"
            ;;
    esac
done)

if [ -z "$files" ]; then
    echo "no-candidates"
    exit 0
fi

total=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
echo "total=$total"

# Print the keep list (newest N)
keep=$(printf '%s\n' "$files" | head -n "$RETAIN")
echo "---keep---"
printf '%s\n' "$keep"

# Print the delete list (everything after the first N)
delete=$(printf '%s\n' "$files" | tail -n "+$((RETAIN + 1))")

if [ -z "$delete" ]; then
    echo "---delete---"
    echo "---done---"
    exit 0
fi

echo "---delete---"
printf '%s\n' "$delete"

if [ "$DRY_RUN" = "1" ]; then
    echo "---done---"
    exit 0
fi

# Delete. Each filename is matched against the dump-*.rdb pattern above
# so it can't contain shell-special characters even before we quote it.
printf '%s\n' "$delete" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    rm -f -- "$BACKUP_DIR/$f"
done

echo "---done---"
REMOTE
)

# Execute remotely. The three placeholders are passed positionally so the
# remote shell never expands them via the literal command string.
set +e
OUTPUT=$(kubectl -n "$NAMESPACE" exec -i "$FDB_POD" -- sh -c "$REMOTE_SCRIPT" _ \
    "$BACKUP_DIR" "$RETAIN" "$DRY_RUN" 2>&1)
RC=$?
set -e

if (( RC != 0 )); then
    err "Remote execution failed (exit $RC)."
    err "Remote output:"
    printf '%s\n' "$OUTPUT" >&2
    exit 3
fi

# Parse output
case "$OUTPUT" in
    no-backup-dir*)
        log "Backup directory '$BACKUP_DIR' does not exist on the pod. Nothing to do."
        exit 0
        ;;
    no-candidates*)
        log "No files matching 'dump-*.rdb' under '$BACKUP_DIR'. Nothing to do."
        exit 0
        ;;
esac

TOTAL=$(printf '%s\n' "$OUTPUT" | awk -F= '/^total=/ {print $2; exit}')
KEEP=$(printf '%s\n' "$OUTPUT" | awk '/^---keep---$/{flag=1;next} /^---/{flag=0} flag')
DELETE=$(printf '%s\n' "$OUTPUT" | awk '/^---delete---$/{flag=1;next} /^---/{flag=0} flag')

log "Found $TOTAL backup file(s)."
log "Keeping (newest $RETAIN):"
if [[ -z "$KEEP" ]]; then
    log "  (none)"
else
    printf '%s\n' "$KEEP" | sed 's/^/    /' >&2
fi

if [[ -z "$DELETE" ]]; then
    log "Nothing to delete - retention already satisfied."
    exit 0
fi

DELETE_COUNT=$(printf '%s\n' "$DELETE" | wc -l | tr -d ' ')
if (( DRY_RUN == 1 )); then
    log "Would delete $DELETE_COUNT file(s) (dry run):"
else
    log "Deleted $DELETE_COUNT file(s):"
fi
printf '%s\n' "$DELETE" | sed 's/^/    /' >&2

log "Done."
