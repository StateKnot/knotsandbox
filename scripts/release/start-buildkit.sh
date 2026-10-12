#!/usr/bin/env bash
# Isolated ephemeral Linux AMD64 builder. Never attach to a pre-existing daemon.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: start-buildkit.sh TOOLS_DIRECTORY STATE_DIRECTORY' >&2; exit 2; }
tools_dir="$(realpath "$1")"
state_dir="$(realpath -m "$2")"
[[ ! -e "$state_dir" && "$(uname -sm)" == 'Linux x86_64' ]] || exit 2
python3 - "$tools_dir" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('scripts/release').resolve()))
from common import tool
for name in ('buildctl', 'buildkitd', 'buildkit-runc'): tool(Path(sys.argv[1]), name)
PY
mkdir -m 0700 -p "$state_dir"
sudo "$tools_dir/buildkitd" --root "$state_dir/root" --addr "unix://$state_dir/buildkit.sock" --group "$(id -gn)" --containerd-worker=false --oci-worker=true --oci-worker-platform=linux/amd64 --oci-worker-net=host --oci-worker-binary "$tools_dir/buildkit-runc" --oci-max-parallelism=2 > "$state_dir/daemon.log" 2>&1 &
daemon_pid=$!
printf '%s\n' "$daemon_pid" > "$state_dir/launcher.pid"
for attempt in {1..30}; do
  if "$tools_dir/buildctl" --addr "unix://$state_dir/buildkit.sock" debug workers >/dev/null 2>&1; then
    printf 'BUILDKIT_HOST=unix://%s/buildkit.sock\n' "$state_dir"
    exit 0
  fi
  kill -0 "$daemon_pid" || { cat "$state_dir/daemon.log" >&2; exit 1; }
  sleep 1
done
exit 1
