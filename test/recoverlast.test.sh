#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --recover-last tests.
#
# --recover-last <contact> --sent|--received streams the kept safety copy
# of the last delivered payload (.keychain/<contact>.last_sent /
# .last_received) to stdout. It must be read-only and idempotent: the copy
# is never deleted by this command - not even after a fully successful
# stream, because bytes leaving the process is not proof they were
# persisted or delivered anywhere. Only the next operation in the same
# direction removes the copy, when delivery is confirmed (-y or an
# interactive yes).
#
# Exit codes under test: 0 copy streamed, 2 no copy exists, 1 error.

rm -rf .keychain
rm -f rl_*

echo ""
echo "   - --recover-last: re-emitting the kept safety copies"

# Two loopback contacts sharing mirrored pads: what rlsend encrypts,
# rlrecv decrypts.
dd if=/dev/urandom of=rl_k1 bs=1 count=4096 2>/dev/null
dd if=/dev/urandom of=rl_k2 bs=1 count=4096 2>/dev/null
./bin/otp --add-contact rlsend rl_k1 rl_k2 > /dev/null 2>&1
./bin/otp --add-contact rlrecv rl_k2 rl_k1 > /dev/null 2>&1

keychain_snapshot() {
  find .keychain -type f | LC_ALL=C sort | xargs cksum
}

# -----------------------------------------------------------------------------
#  errors and the no-copy probe
# -----------------------------------------------------------------------------

echo "     Testing errors and the no-copy case..."

./bin/otp --recover-last nobody --sent > /dev/null 2> rl_err
if [ $? -eq 1 ] && grep -q "not found" rl_err; then
  echo "     - ${GREEN}PASS${NC} - unknown contact: exit 1"
else
  echo "     ! ${RED}FAIL${NC} - unknown contact did not exit 1"
  exit 1
fi

./bin/otp --recover-last rlsend > /dev/null 2> rl_err
if [ $? -eq 1 ] && grep -q "Usage" rl_err; then
  echo "     - ${GREEN}PASS${NC} - missing --sent/--received: exit 1 with usage"
else
  echo "     ! ${RED}FAIL${NC} - missing direction flag not rejected"
  exit 1
fi

./bin/otp --recover-last rlsend --sent > rl_out 2> rl_err
RC=$?
if [ $RC -eq 2 ] && [ "$(wc -c < rl_out | tr -d ' ')" = "0" ] && grep -q "No kept copy" rl_err; then
  echo "     - ${GREEN}PASS${NC} - no copy yet: exit 2, empty stdout (usable as an existence probe)"
else
  echo "     ! ${RED}FAIL${NC} - no-copy case wrong (exit $RC)"
  cat rl_err
  exit 1
fi

# -----------------------------------------------------------------------------
#  --sent re-emits the exact ciphertext, repeatably, without consuming it
# -----------------------------------------------------------------------------

echo "     Testing --sent..."

dd if=/dev/urandom of=rl_plain1 bs=100 count=1 2>/dev/null
OTP_TEST_NO_TTY=1 ./bin/otp -c rlsend --encrypt < rl_plain1 > rl_c1 2>/dev/null
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: encrypt failed"
  exit 1
fi

./bin/otp --recover-last rlsend --sent > rl_r1 2>/dev/null
if [ $? -eq 0 ] && cmp -s rl_r1 rl_c1; then
  echo "     - ${GREEN}PASS${NC} - --sent streams the exact delivered ciphertext (exit 0)"
else
  echo "     ! ${RED}FAIL${NC} - recovered ciphertext differs from what was delivered"
  exit 1
fi

# idempotent: a second recovery is byte-identical and the copy survives both
keychain_snapshot > rl_snap1
./bin/otp --recover-last rlsend --sent > rl_r2 2>/dev/null
keychain_snapshot > rl_snap2
if cmp -s rl_r2 rl_c1 && [ -f ".keychain/rlsend.last_sent" ] && cmp -s rl_snap1 rl_snap2; then
  echo "     - ${GREEN}PASS${NC} - repeatable: second recovery identical, keychain byte-identical"
else
  echo "     ! ${RED}FAIL${NC} - recovery consumed or altered keychain state"
  diff rl_snap1 rl_snap2
  exit 1
fi

# -----------------------------------------------------------------------------
#  --received re-emits the exact plaintext of the last decrypt
# -----------------------------------------------------------------------------

echo "     Testing --received..."

OTP_TEST_NO_TTY=1 ./bin/otp -c rlrecv --decrypt < rl_c1 > rl_p1 2>/dev/null
if ! cmp -s rl_p1 rl_plain1; then
  echo "     ! ${RED}FAIL${NC} - test setup: decrypt round-trip failed"
  exit 1
fi
./bin/otp --recover-last rlrecv --received > rl_rp1 2>/dev/null
if [ $? -eq 0 ] && cmp -s rl_rp1 rl_plain1; then
  echo "     - ${GREEN}PASS${NC} - --received streams the exact delivered plaintext (exit 0)"
else
  echo "     ! ${RED}FAIL${NC} - recovered plaintext differs from what was delivered"
  exit 1
fi

# the directions are independent: rlrecv has no sent copy
./bin/otp --recover-last rlrecv --sent > /dev/null 2>/dev/null
if [ $? -eq 2 ]; then
  echo "     - ${GREEN}PASS${NC} - directions independent: --sent on the receiving side exits 2"
else
  echo "     ! ${RED}FAIL${NC} - --sent found a copy that direction never produced"
  exit 1
fi

# -----------------------------------------------------------------------------
#  only a confirmed operation removes the copy
# -----------------------------------------------------------------------------

echo "     Testing only a confirmed operation removes the copy..."

# confirmation alone removes the copy: -y passes the gate, then the run is
# killed right after the pending publish, before any new copy is made
dd if=/dev/urandom of=rl_plain2 bs=60 count=1 2>/dev/null
OTP_TEST_CRASH_POINT=after_pending_publish OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c rlsend --encrypt < rl_plain2 > /dev/null 2>/dev/null
./bin/otp --recover-last rlsend --sent > /dev/null 2> rl_err
if [ $? -eq 2 ] && grep -q "No kept copy" rl_err; then
  echo "     - ${GREEN}PASS${NC} - after the next confirmed operation, recovery correctly finds no copy"
else
  echo "     ! ${RED}FAIL${NC} - copy lifecycle changed: expected exit 2 after confirmation"
  cat rl_err
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain
rm -f rl_*
echo ""
exit 0
