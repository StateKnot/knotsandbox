#!/usr/bin/env bash
# No apply, no backend connection, and no cloud credentials required.
set -euo pipefail
root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tf_bin="${TF_BIN:-terraform}"
version_output="$("$tf_bin" version)"
version_line="${version_output%%$'\n'*}"
if [[ "$version_line" != 'Terraform v1.14.7' ]]; then
  printf '%s\n' 'Use the pinned Terraform 1.14.7 binary (set TF_BIN if needed).' >&2
  exit 1
fi
export TF_IN_AUTOMATION=1
for module_dir in "$root_dir" "$root_dir/state-bootstrap"; do
  "$tf_bin" -chdir="$module_dir" fmt -check -recursive
  "$tf_bin" -chdir="$module_dir" init -backend=false -input=false -lockfile=readonly
  "$tf_bin" -chdir="$module_dir" validate -no-color
  "$tf_bin" -chdir="$module_dir" test -no-color
done
