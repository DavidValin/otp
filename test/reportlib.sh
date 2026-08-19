# Shared helpers for rendering test-report.html, split out of
# test/report.sh so the PASS/FAIL colorizing logic can be exercised in
# isolation by test/reporthtml.test.sh without re-running the whole suite.

html_escape() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Wraps each assertion line's PASS/FAIL keyword in a <b> tagged with the
# class the report's stylesheet colors (b.pass/b.fail -> var(--pass)/
# var(--fail), green/red). Input must already be HTML-escaped.
colorize_result() {
  sed -e 's/ - \(PASS\)/ - <b class="pass">\1<\/b>/' \
      -e 's/! \(FAIL\)/! <b class="fail">\1<\/b>/'
}

# Same idea as colorize_result, but for the console instead of the HTML
# report: wraps each assertion line's PASS/FAIL keyword in the caller's
# GREEN/RED/NC escape sequences. The caller is expected to have set those
# to empty strings when its own stdout isn't a terminal, which makes this
# a no-op then - the same convention every individual test/*.test.sh
# script already uses for its own output.
colorize_console() {
  sed -e "s/ - PASS/ - ${GREEN}PASS${NC}/" -e "s/! FAIL/! ${RED}FAIL${NC}/"
}
