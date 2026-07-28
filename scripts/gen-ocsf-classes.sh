#!/usr/bin/env bash
#
# Regenerate internal/ocsf/classes.json from an upstream OCSF release.
#
# This is run BY HAND when adopting a new OCSF version — never at build time.
# Console-IR's offline-first guarantee means the build must not depend on
# network access or upstream availability.
#
# Usage:
#   scripts/gen-ocsf-classes.sh [schema-version]
#
# Example:
#   scripts/gen-ocsf-classes.sh 1.8.0
#
# After running, review the diff: new classes are additive and safe, but a
# renamed or removed class changes what analysts see in the UI.

set -euo pipefail

SCHEMA_VERSION="${1:-1.8.0}"
API="https://schema.ocsf.io/api/categories"
OUT="$(dirname "$0")/../internal/ocsf/classes.json"

command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 1; }
command -v jq   >/dev/null || { echo "error: jq is required" >&2; exit 1; }

echo "Fetching OCSF class registry from ${API} ..." >&2
raw="$(curl -fsSL "$API")"

# The API nests classes under .attributes.<category>.classes.<class>, each
# carrying uid (class_uid), caption, and the owning category's uid.
echo "$raw" | jq --arg ver "$SCHEMA_VERSION" --arg src "$API" '
  {
    schema_version: $ver,
    source: $src,
    note: "Vendored point-in-time copy of the OCSF class registry. Refresh with scripts/gen-ocsf-classes.sh.",
    categories: (
      [ .attributes | to_entries[]
        | { uid: .value.uid, name: .value.caption, slug: .key }
      ] | sort_by(.uid)
    ),
    classes: (
      [ .attributes | to_entries[] as $cat
        | ($cat.value.classes // {}) | to_entries[]
        | { uid: .value.uid, name: .value.caption, cat: $cat.value.uid }
      ] | sort_by(.uid)
    )
  }
' > "${OUT}.tmp"

# Sanity-check before overwriting: the Findings classes must be present and
# correctly categorised, since the whole investigation workflow keys on them.
for uid in 2004 2005; do
  got="$(jq --argjson u "$uid" '[.classes[] | select(.uid == $u)] | length' "${OUT}.tmp")"
  [ "$got" = "1" ] || { echo "error: class_uid ${uid} missing from generated registry" >&2; rm -f "${OUT}.tmp"; exit 1; }
done

mv "${OUT}.tmp" "$OUT"
echo "Wrote ${OUT} (OCSF ${SCHEMA_VERSION})" >&2
echo >&2
echo "NOTE: the generated 'slug' values come from upstream category keys and may" >&2
echo "      differ from the short slugs Console-IR persists in events.event_type." >&2
echo "      Review the diff and preserve existing slugs to avoid invalidating" >&2
echo "      stored event_type values." >&2
