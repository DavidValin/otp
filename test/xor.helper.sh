#!/bin/sh

# Shared test helper: XOR two files byte by byte, independently of the
# binary under test. The suites use this to compute the expected result
# of an encrypt/decrypt from a known key slice, so the expectation is
# produced by different code than the code being verified.
#
# xor_with_key <keyfile> <datafile> <outfile>
#   XORs every byte of <datafile> with the byte at the same position of
#   <keyfile> (which must be at least as long) and writes the result to
#   <outfile>. Bytes are round-tripped as decimal via od(1) and combined
#   in awk (bit by bit - POSIX awk has no xor()), then emitted as octal
#   escapes for printf, which handles NUL and every other byte value.
xor_with_key() {
  XW_KEY=$1
  XW_DATA=$2
  XW_OUT=$3
  XW_LEN=$(wc -c < "$XW_DATA" | tr -d ' ')
  XW_ESC=$(
    {
      od -An -v -tu1 "$XW_DATA"
      echo "XORSEP"
      dd if="$XW_KEY" bs=1 count="$XW_LEN" 2>/dev/null | od -An -v -tu1
    } | awk '
      /^XORSEP$/ { insep = 1; next }
      {
        for (i = 1; i <= NF; i++) {
          if (!insep) d[nd++] = $i; else k[nk++] = $i
        }
      }
      END {
        for (j = 0; j < nd; j++) {
          x = 0
          for (b = 1; b < 256; b *= 2)
            if (int(d[j] / b) % 2 != int(k[j] / b) % 2) x += b
          printf "\\%03o", x
        }
      }'
  )
  # The escape string contains only backslash-octal sequences, so it is
  # safe to hand to printf as a format string.
  printf "$XW_ESC" > "$XW_OUT"
}
