#!/usr/bin/env bash
# build.sh — regenerate both decks on-brand from the MeteoSwiss template.
# Pandoc 3.x required (installed under tools/penv via pypandoc_binary).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"               # doc/presentation/build
PRES="$(cd "$HERE/.." && pwd)"                       # doc/presentation
REPO="$(cd "$PRES/../.." && pwd)"
PANDOC="${PANDOC:-$REPO/tools/penv/lib/python3.11/site-packages/pypandoc/files/pandoc}"
[ -x "$PANDOC" ] || PANDOC="$(command -v pandoc)"

bash "$HERE/make-reference.sh"
REF="$PRES/mch-reference.pptx"

for deck in tight full; do
  "$PANDOC" "$HERE/deck-$deck.md" \
    --reference-doc="$REF" --slide-level=2 \
    -o "$PRES/meteoswiss-talk-$deck.pptx"
  echo "built: meteoswiss-talk-$deck.pptx"
done
