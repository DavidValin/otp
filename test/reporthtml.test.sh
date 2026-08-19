#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# Guards test-report.html's own rendering: a FAIL assertion line must come
# out colored red and lined up under the PASS lines around it, using the
# exact html_escape/colorize_result functions test/report.sh renders the
# report with (test/reportlib.sh), so a change to that pipeline is caught
# here instead of only being noticed by eyeballing the generated HTML.

echo ""
echo "   - test-report.html FAIL/PASS rendering"

. test/reportlib.sh

# -----------------------------------------------------------------------------
#  a FAIL line is wrapped in the red-colored b.fail span, a PASS line in
#  the green-colored b.pass span - matching the classes report.sh's own
#  stylesheet colors from --pass/--fail
# -----------------------------------------------------------------------------
SAMPLE=$(printf '     - PASS - something worked\n     ! FAIL - something broke\n')
RENDERED=$(printf '%s\n' "$SAMPLE" | html_escape | colorize_result)

if printf '%s\n' "$RENDERED" | grep -qF '! <b class="fail">FAIL</b> - something broke'; then
  echo "     - ${GREEN}PASS${NC} - a FAIL assertion is wrapped in the red-colored b.fail span"
else
  echo "     ! ${RED}FAIL${NC} - FAIL text was not wrapped in <b class=\"fail\">: $RENDERED"
  exit 1
fi

if printf '%s\n' "$RENDERED" | grep -qF -- '- <b class="pass">PASS</b> - something worked'; then
  echo "     - ${GREEN}PASS${NC} - a PASS assertion is wrapped in the green-colored b.pass span"
else
  echo "     ! ${RED}FAIL${NC} - PASS text was not wrapped in <b class=\"pass\">: $RENDERED"
  exit 1
fi

# -----------------------------------------------------------------------------
#  alignment: PASS and FAIL keywords must start at the same column so the
#  badges line up under each other - true as long as their marker char
#  ('-' for PASS, '!' for FAIL) is a single byte, but assert it directly
#  so a future marker change (e.g. a multi-char prefix) cannot go unnoticed
# -----------------------------------------------------------------------------
PASS_LINE=$(printf '%s\n' "$SAMPLE" | grep 'PASS')
FAIL_LINE=$(printf '%s\n' "$SAMPLE" | grep 'FAIL')
PASS_COL=$(printf '%s' "$PASS_LINE" | awk '{print index($0,"PASS")}')
FAIL_COL=$(printf '%s' "$FAIL_LINE" | awk '{print index($0,"FAIL")}')

if [ "$PASS_COL" -eq "$FAIL_COL" ]; then
  echo "     - ${GREEN}PASS${NC} - PASS and FAIL keywords start at the same column ($PASS_COL)"
else
  echo "     ! ${RED}FAIL${NC} - PASS starts at column $PASS_COL but FAIL starts at column $FAIL_COL"
  exit 1
fi

# -----------------------------------------------------------------------------
#  the stylesheet report.sh embeds must define distinct, non-empty red and
#  green hex colors for --fail/--pass, and color b.fail/b.pass from them -
#  otherwise the spans above would render in the default text color
# -----------------------------------------------------------------------------
if grep -qE -- '--pass: #[0-9a-fA-F]{6}; --fail: #[0-9a-fA-F]{6};' test/report.sh; then
  echo "     - ${GREEN}PASS${NC} - stylesheet defines distinct --pass/--fail colors"
else
  echo "     ! ${RED}FAIL${NC} - stylesheet is missing the --pass/--fail color variables"
  exit 1
fi

if grep -qF 'b.pass { color: var(--pass); } b.fail { color: var(--fail); }' test/report.sh; then
  echo "     - ${GREEN}PASS${NC} - b.pass/b.fail are colored from the --pass/--fail variables"
else
  echo "     ! ${RED}FAIL${NC} - b.pass/b.fail coloring rule not found or changed shape"
  exit 1
fi

echo ""
exit 0
