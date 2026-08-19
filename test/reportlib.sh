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
