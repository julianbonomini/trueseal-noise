#!/usr/bin/env bash
# Fails unless a release tag (vX.Y.Z) matches the package version in Cargo.toml.
# Usage: scripts/check-tag-version.sh <tag> [path/to/Cargo.toml]
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <tag> [Cargo.toml]" >&2
  exit 2
fi

tag="$1"
manifest="${2:-Cargo.toml}"

if ! [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "error: tag '$tag' is not of the form vX.Y.Z" >&2
  exit 1
fi
tag_version="${BASH_REMATCH[1]}"

# First `version = "..."` inside the [package] table.
cargo_version="$(awk '
  /^\[/ { in_pkg = ($0 == "[package]") ; next }
  in_pkg && /^version[[:space:]]*=/ {
    match($0, /"[^"]*"/)
    print substr($0, RSTART + 1, RLENGTH - 2)
    exit
  }
' "$manifest")"

if [ -z "$cargo_version" ]; then
  echo "error: no [package] version found in $manifest" >&2
  exit 1
fi

if [ "$tag_version" != "$cargo_version" ]; then
  echo "error: tag $tag does not match Cargo.toml version $cargo_version" >&2
  exit 1
fi

echo "ok: tag $tag matches Cargo.toml version $cargo_version"
