#!/usr/bin/env bash
# make-reference.sh — turn the MeteoSwiss template into a pandoc-compatible
# --reference-doc by (a) renaming slide layouts to pandoc's standard names and
# (b) retyping the content placeholders to the idx/typeless form pandoc emits.
# Output: mch-reference.pptx next to the template.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # doc/presentation
TPL="${1:-$HERE/99999999_Template_EN.pptx}"
OUT="${2:-$HERE/mch-reference.pptx}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
unzip -o -q "$TPL" -d "$W"
LD="$W/ppt/slideLayouts"
rn(){ perl -0pi -e "s/<p:cSld name=\"[^\"]*\"/<p:cSld name=\"$2\"/" "$LD/slideLayout$1.xml"; }
# layout#  pandoc name              (template orig / structure)
rn 2  "Title Slide"          # ctrTitle + subTitle idx1   (already matches pandoc)
rn 4  "Title and Content"    # title   + typeless idx1     (already matches pandoc)
rn 6  "Section Header"       # title   + body idx13 -> idx1
rn 8  "Title Only"
rn 10 "Two Content"          # title   + body idx13/14 -> typeless idx1/idx2
rn 9  "Comparison"
rn 14 "Content with Caption"
rn 13 "Picture with Caption"
rn 18 "Blank"
# placeholder surgery so slide content lands in the MeteoSwiss-positioned boxes
perl -0pi -e 's/<p:ph type="body" idx="13"\/>/<p:ph type="body" idx="1"\/>/' "$LD/slideLayout6.xml"
perl -0pi -e 's/<p:ph type="body" idx="13"\/>/<p:ph idx="1"\/>/'            "$LD/slideLayout10.xml"
perl -0pi -e 's/<p:ph type="body" idx="14"\/>/<p:ph idx="2"\/>/'            "$LD/slideLayout10.xml"
rm -f "$OUT"; ( cd "$W" && zip -r -X -q "$OUT" . )
echo "built: $OUT"
