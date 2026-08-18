#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --add-rand-to-vault tests.
#
# cat /dev/urandom | otp --add-rand-to-vault <N_MB> stores a sequential
# randomness stream at .keychain/_randomness - not tied to any contact.
# A first call creates the file (mode 0600); every later call appends,
# byte for byte, to whatever is already there.

rm -rf .keychain
rm -f rv_*

echo ""
echo "   - --add-rand-to-vault: the randomness vault"

# -----------------------------------------------------------------------------
#  creating the vault
# -----------------------------------------------------------------------------

echo "     Testing vault creation..."

dd if=/dev/urandom of=rv_src1 bs=1048576 count=1 2>/dev/null

if [ -e .keychain/_randomness ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: vault already exists before first call"
  exit 1
fi

cat rv_src1 | ./bin/otp --add-rand-to-vault 1 > rv_out1 2> rv_err1
RC=$?
if [ $RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - first call exits 0"
else
  echo "     ! ${RED}FAIL${NC} - first call failed (exit $RC): $(cat rv_err1)"
  exit 1
fi

if [ -f .keychain/_randomness ]; then
  echo "     - ${GREEN}PASS${NC} - vault file created at .keychain/_randomness"
else
  echo "     ! ${RED}FAIL${NC} - vault file was not created"
  exit 1
fi

# Report format: OK, a blank line, then the amount just added and the
# vault's new running total - both checked byte-exact.
if [ "$(sed -n '1p' rv_out1)" = "OK" ] && [ -z "$(sed -n '2p' rv_out1)" ]; then
  echo "     - ${GREEN}PASS${NC} - reports OK on its own line, followed by a blank line"
else
  echo "     ! ${RED}FAIL${NC} - expected OK then a blank line, got: $(cat rv_out1)"
  exit 1
fi
if grep -q "$(printf '\033')" rv_out1; then
  echo "     ! ${RED}FAIL${NC} - ANSI escape codes leaked into non-terminal output"
  exit 1
else
  echo "     - ${GREEN}PASS${NC} - output is plain text when stdout is not a terminal"
fi
if grep -q "^Added: 1 MB (1048576 bytes)$" rv_out1 && grep -q "^Vault total: 1.00 MB (1048576 bytes)$" rv_out1; then
  echo "     - ${GREEN}PASS${NC} - summary reports the amount added and the vault's running total"
else
  echo "     ! ${RED}FAIL${NC} - summary missing or wrong: $(cat rv_out1)"
  exit 1
fi

# Permissions: 0600, like every other secret this tool writes to .keychain/.
PERM=$(stat -c "%a" .keychain/_randomness 2>/dev/null || stat -f "%Lp" .keychain/_randomness 2>/dev/null)
if [ "$PERM" = "600" ]; then
  echo "     - ${GREEN}PASS${NC} - vault file created with mode 0600"
else
  echo "     ! ${RED}FAIL${NC} - vault file mode is $PERM, expected 600"
  exit 1
fi

if cmp -s .keychain/_randomness rv_src1; then
  echo "     - ${GREEN}PASS${NC} - vault content is exactly the streamed randomness (same bits)"
else
  echo "     ! ${RED}FAIL${NC} - vault content differs from what was piped in"
  exit 1
fi

# Same per-name flock() protection as a contact: a lock file alongside
# the vault, so concurrent invocations can never interleave writes.
if [ -f .keychain/_randomness.lock ]; then
  echo "     - ${GREEN}PASS${NC} - vault lock file .keychain/_randomness.lock created"
else
  echo "     ! ${RED}FAIL${NC} - no lock file created alongside the vault"
  exit 1
fi

# -----------------------------------------------------------------------------
#  appending to an existing vault
# -----------------------------------------------------------------------------

echo "     Testing appending to an existing vault..."

dd if=/dev/urandom of=rv_src2 bs=1048576 count=2 2>/dev/null

cat rv_src2 | ./bin/otp --add-rand-to-vault 2 > rv_out2 2> rv_err2
RC=$?
if [ $RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - second call exits 0"
else
  echo "     ! ${RED}FAIL${NC} - second call failed (exit $RC): $(cat rv_err2)"
  exit 1
fi

cat rv_src1 rv_src2 > rv_expected
SZ_EXPECTED=$(wc -c < rv_expected | tr -d ' ')
SZ_ACTUAL=$(wc -c < .keychain/_randomness | tr -d ' ')
if [ "$SZ_ACTUAL" = "$SZ_EXPECTED" ]; then
  echo "     - ${GREEN}PASS${NC} - vault size is the sum of both calls ($SZ_ACTUAL bytes)"
else
  echo "     ! ${RED}FAIL${NC} - vault size $SZ_ACTUAL does not match expected $SZ_EXPECTED"
  exit 1
fi

if cmp -s .keychain/_randomness rv_expected; then
  echo "     - ${GREEN}PASS${NC} - new randomness is appended after the existing content, byte for byte"
else
  echo "     ! ${RED}FAIL${NC} - appended vault content does not match old+new concatenation"
  exit 1
fi

if grep -q "^Added: 2 MB (2097152 bytes)$" rv_out2 && grep -q "^Vault total: 3.00 MB (3145728 bytes)$" rv_out2; then
  echo "     - ${GREEN}PASS${NC} - second call's summary reports the running total (existing + new), not just the new amount"
else
  echo "     ! ${RED}FAIL${NC} - append summary missing or wrong: $(cat rv_out2)"
  exit 1
fi

# a third call must append after the second, not overwrite it
dd if=/dev/urandom of=rv_src3 bs=524288 count=1 2>/dev/null
cat rv_src3 | ./bin/otp --add-rand-to-vault 0.5 > /dev/null 2> rv_err3
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - third (fractional-MB) call failed: $(cat rv_err3)"
  exit 1
fi
cat rv_expected rv_src3 > rv_expected2
if cmp -s .keychain/_randomness rv_expected2; then
  echo "     - ${GREEN}PASS${NC} - a third call (fractional MB) appends after both previous ones"
else
  echo "     ! ${RED}FAIL${NC} - third append corrupted or overwrote earlier vault content"
  exit 1
fi

# -----------------------------------------------------------------------------
#  input validation
# -----------------------------------------------------------------------------

echo "     Testing input validation..."

cp .keychain/_randomness rv_before_bad

echo "not a size" | ./bin/otp --add-rand-to-vault notanumber > /dev/null 2>rv_err4
if [ $? -ne 0 ] && cmp -s .keychain/_randomness rv_before_bad; then
  echo "     - ${GREEN}PASS${NC} - non-numeric size rejected, vault left untouched"
else
  echo "     ! ${RED}FAIL${NC} - non-numeric size should be rejected without touching the vault"
  exit 1
fi

echo "" | ./bin/otp --add-rand-to-vault 0 > /dev/null 2>rv_err5
if [ $? -ne 0 ] && cmp -s .keychain/_randomness rv_before_bad; then
  echo "     - ${GREEN}PASS${NC} - zero size rejected, vault left untouched"
else
  echo "     ! ${RED}FAIL${NC} - zero size should be rejected without touching the vault"
  exit 1
fi

# stdin shorter than the declared size must be rejected, not silently
# padded or truncated into the vault as if it were the full request
printf 'short' | ./bin/otp --add-rand-to-vault 1 > /dev/null 2>rv_err6
if [ $? -ne 0 ] && cmp -s .keychain/_randomness rv_before_bad; then
  echo "     - ${GREEN}PASS${NC} - short stdin rejected, vault left at its prior content"
else
  echo "     ! ${RED}FAIL${NC} - short stdin should be rejected without corrupting the vault"
  exit 1
fi

# -----------------------------------------------------------------------------
#  refuses a terminal stdin, like --new-key-pair
# -----------------------------------------------------------------------------
# Run with stdin attached to a pseudo-terminal (via script(1)) instead of a
# pipe: it must refuse immediately, before touching the vault, rather than
# block waiting for typed randomness. script's own stdin is /dev/null so
# even a regression (no refusal) ends with a read error instead of hanging.

echo "     Testing terminal stdin is refused..."

cp .keychain/_randomness rv_before_tty

TTY_TESTED=""
if script --version 2>/dev/null | grep -q util-linux; then
  TTY_OUT=$(script -qec "./bin/otp --add-rand-to-vault 1" /dev/null < /dev/null 2>&1)
  TTY_TESTED=1
elif [ "$(uname)" = "Darwin" ]; then
  TTY_OUT=$(script -q /dev/null ./bin/otp --add-rand-to-vault 1 < /dev/null 2>&1)
  TTY_TESTED=1
fi

if [ -z "$TTY_TESTED" ]; then
  echo "     - SKIP - no way to allocate a pseudo-terminal on this platform"
else
  if printf '%s' "$TTY_OUT" | grep -q "stdin is a terminal"; then
    echo "     - ${GREEN}PASS${NC} - refused when stdin is a terminal"
  else
    echo "     ! ${RED}FAIL${NC} - expected a refusal when stdin is a terminal, got: $TTY_OUT"
    exit 1
  fi
  if cmp -s .keychain/_randomness rv_before_tty; then
    echo "     - ${GREEN}PASS${NC} - refused run left the vault untouched"
  else
    echo "     ! ${RED}FAIL${NC} - refused run modified the vault"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
#  concurrent invocations are serialized, never interleaved or corrupted
# -----------------------------------------------------------------------------
# Five processes each append a distinct 1MB block, all filled with their
# own single repeated byte value, concurrently. If the vault's lock ever
# let two writers interleave, at least one 1MB slice of the result would
# mix two different byte values; if a writer's data were lost or
# duplicated, the total size or the set of five values would come out
# wrong. Checking neither happens is a lock-loss and torn-write detector
# that needs no knowledge of write ordering, since the five processes may
# finish in any order.

echo "     Testing concurrent invocations don't interleave or corrupt..."

rm -rf .keychain
rm -f rv_chunk_*

BLOCK=1048576
i=1
for byte in 11 22 33 44 55; do
  dd if=/dev/zero bs=$BLOCK count=1 2>/dev/null | tr '\0' "$(printf "\\$(printf '%03o' 0x$byte)")" > rv_chunk_$i
  i=$((i + 1))
done

for i in 1 2 3 4 5; do
  (cat rv_chunk_$i | ./bin/otp --add-rand-to-vault 1 > rv_cout_$i 2>&1) &
done
wait

ALL_OK=1
for i in 1 2 3 4 5; do
  if ! grep -q "^Added" rv_cout_$i; then
    ALL_OK=0
  fi
done
SZ=$(wc -c < .keychain/_randomness | tr -d ' ')
if [ "$ALL_OK" = "1" ] && [ "$SZ" = "$((BLOCK * 5))" ]; then
  echo "     - ${GREEN}PASS${NC} - all five concurrent calls succeeded, vault size is the exact sum ($SZ bytes)"
else
  echo "     ! ${RED}FAIL${NC} - concurrent calls did not all succeed or vault size is wrong ($SZ, expected $((BLOCK * 5)))"
  exit 1
fi

# Walk the vault in 1MB slices; each must be internally uniform (a single
# repeated byte), and together the five slices must be exactly the five
# distinct values written, each appearing once - in whatever order the
# processes happened to finish in.
CORRUPT=0
SEEN=""
n=0
while [ $n -lt 5 ]; do
  dd if=.keychain/_randomness bs=$BLOCK skip=$n count=1 2>/dev/null > rv_slice
  # -v disables od's default elision of repeated identical output lines
  # with a "*" marker - without it, a uniform 1MB slice collapses to one
  # line and a run at an offset boundary can look like two values.
  DISTINCT=$(od -v -An -tx1 rv_slice | tr -s ' \n' '\n' | grep -v '^$' | sort -u | wc -l | tr -d ' ')
  if [ "$DISTINCT" != "1" ]; then
    CORRUPT=1
  fi
  VAL=$(od -An -tx1 -N1 rv_slice | tr -d ' \n')
  SEEN="$SEEN $VAL"
  n=$((n + 1))
done
rm -f rv_slice

SORTED_SEEN=$(printf '%s\n' $SEEN | sort | tr '\n' ' ')
if [ "$CORRUPT" = "0" ] && [ "$SORTED_SEEN" = "11 22 33 44 55 " ]; then
  echo "     - ${GREEN}PASS${NC} - each 1MB slice is uniform and all five distinct values are present exactly once"
else
  echo "     ! ${RED}FAIL${NC} - vault content shows interleaving/corruption (slice values: $SEEN, any non-uniform: $CORRUPT)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain
rm -f rv_*
echo ""
exit 0
