#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# Last-payload safety-copy tests.
#
# Every keychain encrypt/decrypt keeps an exact copy of what it wrote to
# stdout - .keychain/<contact>.last_sent (ciphertext) or
# .keychain/<contact>.last_received (plaintext) - because the key bytes
# that produced it are destroyed in the same run: a user who forgot to
# redirect stdout would otherwise have lost the message unrecoverably.
# The copy is removed exactly when the next operation in that direction
# confirms delivery (interactive "yes" or -y/OTP_ASSUME_DELIVERED); when
# delivery is rejected, the operator is offered recovery of the copy to a
# file of their choosing, and the copy stays.
#
# Driven through the same test hooks the confirmation gate uses
# (OTP_TEST_CONFIRM_ANSWER, OTP_TEST_NO_TTY) plus the recovery ones
# (OTP_TEST_RECOVER_ANSWER, OTP_TEST_RECOVER_PATH).

rm -rf .keychain
rm -f lc_*

echo ""
echo "   - Last-payload safety copies"

# Two loopback contacts sharing mirrored pads: what lcsend encrypts,
# lcrecv decrypts.
dd if=/dev/urandom of=lc_k1 bs=1 count=4096 2>/dev/null
dd if=/dev/urandom of=lc_k2 bs=1 count=4096 2>/dev/null
./bin/otp --add-contact lcsend lc_k1 lc_k2 > /dev/null 2>&1
./bin/otp --add-contact lcrecv lc_k2 lc_k1 > /dev/null 2>&1

# -----------------------------------------------------------------------------
#  an encrypt keeps its exact ciphertext as <contact>.last_sent
# -----------------------------------------------------------------------------

echo "     Testing the copies are kept..."

dd if=/dev/urandom of=lc_plain1 bs=100 count=1 2>/dev/null
OTP_TEST_NO_TTY=1 ./bin/otp -c lcsend --encrypt < lc_plain1 > lc_c1 2>/dev/null
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: first encrypt failed"
  exit 1
fi
if [ -f ".keychain/lcsend.last_sent" ] && cmp -s .keychain/lcsend.last_sent lc_c1; then
  echo "     - ${GREEN}PASS${NC} - encrypt keeps its exact ciphertext as .last_sent"
else
  echo "     ! ${RED}FAIL${NC} - .keychain/lcsend.last_sent missing or differs from the delivered ciphertext"
  exit 1
fi

# -----------------------------------------------------------------------------
#  a decrypt keeps its exact plaintext as <contact>.last_received
# -----------------------------------------------------------------------------

OTP_TEST_NO_TTY=1 ./bin/otp -c lcrecv --decrypt < lc_c1 > lc_p1 2>/dev/null
if ! cmp -s lc_p1 lc_plain1; then
  echo "     ! ${RED}FAIL${NC} - test setup: decrypt round-trip failed"
  exit 1
fi
if [ -f ".keychain/lcrecv.last_received" ] && cmp -s .keychain/lcrecv.last_received lc_plain1; then
  echo "     - ${GREEN}PASS${NC} - decrypt keeps its exact plaintext as .last_received"
else
  echo "     ! ${RED}FAIL${NC} - .keychain/lcrecv.last_received missing or differs from the delivered plaintext"
  exit 1
fi

# -----------------------------------------------------------------------------
#  an interactive "yes" removes the previous copy (it is then replaced by
#  the new operation's own copy)
# -----------------------------------------------------------------------------

echo "     Testing confirmation removes the previous copy..."

dd if=/dev/urandom of=lc_plain2 bs=120 count=1 2>/dev/null
OTP_TEST_CONFIRM_ANSWER=y ./bin/otp -c lcsend --encrypt < lc_plain2 > lc_c2 2>/dev/null
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - confirmed second encrypt failed"
  exit 1
fi
if cmp -s .keychain/lcsend.last_sent lc_c2 && ! cmp -s .keychain/lcsend.last_sent lc_c1; then
  echo "     - ${GREEN}PASS${NC} - interactive yes: old .last_sent removed, replaced by the new ciphertext"
else
  echo "     ! ${RED}FAIL${NC} - .last_sent was not replaced after a confirmed operation"
  exit 1
fi

# same via -y on the decrypt side
./bin/otp -c lcrecv --decrypt -y < lc_c2 > lc_p2 2>/dev/null
if cmp -s .keychain/lcrecv.last_received lc_plain2 && ! cmp -s .keychain/lcrecv.last_received lc_plain1; then
  echo "     - ${GREEN}PASS${NC} - -y: old .last_received removed, replaced by the new plaintext"
else
  echo "     ! ${RED}FAIL${NC} - .last_received was not replaced after a -y operation"
  exit 1
fi

# -----------------------------------------------------------------------------
#  a rejected confirmation keeps the copy; declining recovery writes nothing
# -----------------------------------------------------------------------------

echo "     Testing rejection keeps the copy..."

dd if=/dev/urandom of=lc_plain3 bs=90 count=1 2>/dev/null
OTP_TEST_CONFIRM_ANSWER=n OTP_TEST_RECOVER_ANSWER=n \
  ./bin/otp -c lcsend --encrypt < lc_plain3 > lc_c3 2> lc_err
RC=$?
if [ $RC -ne 0 ] && [ "$(wc -c < lc_c3 | tr -d ' ')" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - rejected operation cancelled with no output"
else
  echo "     ! ${RED}FAIL${NC} - rejected operation produced output or exited 0 (exit $RC)"
  exit 1
fi
if cmp -s .keychain/lcsend.last_sent lc_c2 && grep -q "kept at" lc_err; then
  echo "     - ${GREEN}PASS${NC} - copy kept after rejection, and the user is told where"
else
  echo "     ! ${RED}FAIL${NC} - copy missing/changed after rejection, or no kept-at notice"
  cat lc_err
  exit 1
fi

# -----------------------------------------------------------------------------
#  rejection + accepted recovery writes the copy to the chosen path
# -----------------------------------------------------------------------------

echo "     Testing recovery to a file..."

rm -f lc_recovered
OTP_TEST_CONFIRM_ANSWER=n OTP_TEST_RECOVER_ANSWER=y OTP_TEST_RECOVER_PATH=lc_recovered \
  ./bin/otp -c lcsend --encrypt < lc_plain3 > /dev/null 2> lc_err
if [ $? -ne 0 ] && cmp -s lc_recovered lc_c2 &&
   cmp -s lc_recovered .keychain/lcsend.last_sent && grep -q "Recovered" lc_err; then
  echo "     - ${GREEN}PASS${NC} - rejected ciphertext recovered byte-exact to the chosen file"
else
  echo "     ! ${RED}FAIL${NC} - recovery did not produce the previous ciphertext"
  cat lc_err
  exit 1
fi
if cmp -s .keychain/lcsend.last_sent lc_c2; then
  echo "     - ${GREEN}PASS${NC} - kept copy still present after recovery (until a later confirmation)"
else
  echo "     ! ${RED}FAIL${NC} - kept copy vanished after recovery"
  exit 1
fi

# recovery must never overwrite an existing file
printf 'precious' > lc_existing
OTP_TEST_CONFIRM_ANSWER=n OTP_TEST_RECOVER_ANSWER=y OTP_TEST_RECOVER_PATH=lc_existing \
  ./bin/otp -c lcsend --encrypt < lc_plain3 > /dev/null 2> lc_err
if [ "$(cat lc_existing)" = "precious" ] && grep -q "cannot create" lc_err; then
  echo "     - ${GREEN}PASS${NC} - recovery refuses to overwrite an existing file"
else
  echo "     ! ${RED}FAIL${NC} - recovery overwrote (or failed to refuse) an existing file"
  cat lc_err
  exit 1
fi

# an empty path cancels recovery, keeping the copy
OTP_TEST_CONFIRM_ANSWER=n OTP_TEST_RECOVER_ANSWER=y OTP_TEST_RECOVER_PATH= \
  ./bin/otp -c lcsend --encrypt < lc_plain3 > /dev/null 2> lc_err
if grep -q "No path given" lc_err && cmp -s .keychain/lcsend.last_sent lc_c2; then
  echo "     - ${GREEN}PASS${NC} - empty recovery path cancels, copy kept"
else
  echo "     ! ${RED}FAIL${NC} - empty recovery path mishandled"
  cat lc_err
  exit 1
fi

# -----------------------------------------------------------------------------
#  decrypt-side rejection + recovery of the previous plaintext
# -----------------------------------------------------------------------------

# The incoming message must be a VALID next message (correct source_id,
# seq and offset): a replayed or garbled one is rejected by the metadata
# layer before the confirmation gate - and its recovery offer - is ever
# reached. Build message #3 at the offset the two decrypts above left.
. test/xor.helper.sh
LC_P1=$(wc -c < lc_plain1 | tr -d ' ')
LC_P2=$(wc -c < lc_plain2 | tr -d ' ')
LC_DC1=$(meta_consumed_len "$LC_P1" 1 0)
LC_DC2=$(meta_consumed_len "$LC_P2" 2 "$LC_DC1")
LC_DOFF3=$((LC_DC1 + LC_DC2))
printf 'a valid third incoming message' > lc_plain_next
make_cipher lc_k1 "$LC_DOFF3" lc_plain_next 3 "$LC_DOFF3" lc_c_next

rm -f lc_recovered_plain
OTP_TEST_CONFIRM_ANSWER=n OTP_TEST_RECOVER_ANSWER=y OTP_TEST_RECOVER_PATH=lc_recovered_plain \
  ./bin/otp -c lcrecv --decrypt < lc_c_next > /dev/null 2> lc_err
if [ $? -ne 0 ] && cmp -s lc_recovered_plain lc_plain2 && cmp -s .keychain/lcrecv.last_received lc_plain2; then
  echo "     - ${GREEN}PASS${NC} - rejected plaintext recovered byte-exact, copy kept"
else
  echo "     ! ${RED}FAIL${NC} - decrypt-side recovery did not produce the previous plaintext"
  cat lc_err
  exit 1
fi

# -----------------------------------------------------------------------------
#  a later confirmed operation finally removes and replaces the copy
# -----------------------------------------------------------------------------

OTP_TEST_CONFIRM_ANSWER=yes ./bin/otp -c lcsend --encrypt < lc_plain3 > lc_c3 2>/dev/null
if [ $? -eq 0 ] && [ "$(wc -c < lc_c3 | tr -d ' ')" != "0" ] && cmp -s .keychain/lcsend.last_sent lc_c3; then
  echo "     - ${GREEN}PASS${NC} - later confirmation replaces the kept copy with the new payload"
else
  echo "     ! ${RED}FAIL${NC} - kept copy not replaced after eventual confirmation"
  exit 1
fi

# -----------------------------------------------------------------------------
#  confirmation ALONE removes the copy: -y passes the gate (removing the
#  previous copy), then the run is killed right after the pending publish
#  - before any new copy is made - so the file must simply be gone. The
#  next run discards the uncommitted pending artifact (no key was spent).
# -----------------------------------------------------------------------------

echo "     Testing confirmation alone removes the copy..."

if [ ! -f ".keychain/lcsend.last_sent" ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: expected a kept copy before the crash run"
  exit 1
fi
dd if=/dev/urandom of=lc_plain5 bs=60 count=1 2>/dev/null
OTP_TEST_CRASH_POINT=after_pending_publish OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c lcsend --encrypt < lc_plain5 > /dev/null 2>/dev/null
if [ ! -f ".keychain/lcsend.last_sent" ]; then
  echo "     - ${GREEN}PASS${NC} - -y confirmation removed the copy even though the new operation never completed"
else
  echo "     ! ${RED}FAIL${NC} - copy survived a confirmed (but interrupted) operation"
  exit 1
fi

# -----------------------------------------------------------------------------
#  a redelivered (crash-recovered) payload is kept as the copy too
# -----------------------------------------------------------------------------

echo "     Testing redelivery refreshes the copy..."

# Crash AFTER the key is truncated (after_key_publish): key material is
# spent, so the next run must redeliver the pending ciphertext (exit 8)
# rather than discard it - and must keep it as the .last_sent copy.
dd if=/dev/urandom of=lc_plain4 bs=80 count=1 2>/dev/null
OTP_TEST_CRASH_POINT=after_key_publish OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c lcsend --encrypt < lc_plain4 > /dev/null 2>/dev/null
printf 'new input, must be ignored' | OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c lcsend --encrypt > lc_c4 2>/dev/null
RC=$?
if [ $RC -eq 8 ] && [ "$(wc -c < lc_c4 | tr -d ' ')" != "0" ] && cmp -s .keychain/lcsend.last_sent lc_c4; then
  echo "     - ${GREEN}PASS${NC} - redelivered ciphertext kept as .last_sent"
else
  echo "     ! ${RED}FAIL${NC} - redelivery (exit $RC) did not refresh .last_sent"
  exit 1
fi

# -----------------------------------------------------------------------------
#  removing a contact removes its kept copies (message content must go)
# -----------------------------------------------------------------------------

echo "     Testing contact removal deletes the copies..."

./bin/otp --remove-contact lcsend > /dev/null 2>&1
./bin/otp --remove-contact lcrecv > /dev/null 2>&1
if [ ! -f ".keychain/lcsend.last_sent" ] && [ ! -f ".keychain/lcrecv.last_received" ]; then
  echo "     - ${GREEN}PASS${NC} - kept copies removed with their contact"
else
  echo "     ! ${RED}FAIL${NC} - a kept copy survived contact removal"
  ls .keychain/
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain
rm -f lc_*
echo ""
exit 0
