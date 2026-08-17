#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# Delivery-confirmation gate tests.
#
# The ciphertext otp emits carries no key-range tag, so within one
# direction messages are only decryptable if they arrive in the exact
# order sent, complete, exactly once - a property only the correspondents
# can verify, out of band. Before spending key on any message after a
# direction's first, otp therefore asks on the terminal whether the
# previous message in that direction arrived intact, and cancels the
# operation - with provably zero key consumed - unless answered yes.
# -y/--assume-delivered (or OTP_ASSUME_DELIVERED=1) records that the
# operator already confirmed out of band; with no terminal and no such
# flag the gate fails closed rather than assuming delivery.
#
# These tests drive the gate deterministically through two test-only
# hooks (same family as OTP_TEST_CRASH_POINT): OTP_TEST_CONFIRM_ANSWER
# stands in for the terminal read, and OTP_TEST_NO_TTY simulates a
# process with no controlling terminal.

rm -rf .keychain

echo ""
echo "   - Delivery-confirmation gate"

# helper: ciphertext for PLAINFILE against KEYFILE at offset OFF -> OUT
confirm_cipher() {
  KEYFILE=$1
  PLAINFILE=$2
  OFF=$3
  OUT=$4
  LEN=$(wc -c < "$PLAINFILE" | tr -d ' ')
  dd if="$KEYFILE" of=confirm_slice.tmp bs=1 skip="$OFF" count="$LEN" 2>/dev/null
  ./bin/otp confirm_slice.tmp < "$PLAINFILE" > "$OUT" 2>/dev/null
  rm -f confirm_slice.tmp confirm_slice.tmp.*.next
}

dd if=/dev/urandom of=confirm_key1.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=confirm_key1.txt.dec bs=1 count=1000 2>/dev/null
./bin/otp --add-contact confirm1 confirm_key1.txt confirm_key1.txt.dec > /dev/null 2>&1

# -----------------------------------------------------------------------------
#  the first message in a direction needs no confirmation: there is no
#  previous message to confirm, so it must succeed even with no terminal
#  and no -y
# -----------------------------------------------------------------------------

echo "     Testing first message needs no confirmation..."

printf 'first message' > confirm_plain1.txt
OTP_TEST_NO_TTY=1 ./bin/otp -c confirm1 --encrypt < confirm_plain1.txt > confirm_c1.bin 2>confirm_err.log
if [ $? -eq 0 ] && [ "$(wc -c < confirm_c1.bin | tr -d ' ')" = "13" ]; then
  echo "     - ${GREEN}PASS${NC} - first message encrypted without prompting"
else
  echo "     ! ${RED}FAIL${NC} - first message should not require confirmation"
  cat confirm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  the second message must prompt, naming the previous message's sequence
#  and the key offset boundary, and proceed on an explicit yes
# -----------------------------------------------------------------------------

echo "     Testing prompt fires on the second message and 'y' proceeds..."

printf 'second here!' > confirm_plain2.txt
OTP_TEST_CONFIRM_ANSWER=y ./bin/otp -c confirm1 --encrypt < confirm_plain2.txt > confirm_c2.bin 2>confirm_err.log
STATUS=$?
if [ $STATUS -eq 0 ] && [ "$(wc -c < confirm_c2.bin | tr -d ' ')" = "12" ]; then
  echo "     - ${GREEN}PASS${NC} - second message encrypted after confirmation"
else
  echo "     ! ${RED}FAIL${NC} - confirmed encrypt failed (exit $STATUS)"
  cat confirm_err.log
  exit 1
fi

if grep -q "Confirmation required" confirm_err.log &&
   grep -q "message: #1" confirm_err.log &&
   grep -q "key consumed up to offset 13" confirm_err.log &&
   grep -q "key bytes 13-25" confirm_err.log; then
  echo "     - ${GREEN}PASS${NC} - prompt names the previous sequence and the key offsets"
else
  echo "     ! ${RED}FAIL${NC} - prompt is missing sequence/offset details"
  cat confirm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  answering no must cancel with the key file, metadata and keychain
#  directory untouched - no artifact, no staging file, no consumed key
# -----------------------------------------------------------------------------

echo "     Testing 'n' cancels with keys provably intact..."

cp .keychain/confirm1_enc.key confirm_key_before.snap
cp .keychain/confirm1.meta confirm_meta_before.snap

printf 'never sent' > confirm_plain3.txt
OTP_TEST_CONFIRM_ANSWER=n ./bin/otp -c confirm1 --encrypt < confirm_plain3.txt > confirm_c3.bin 2>confirm_err.log
STATUS=$?
if [ $STATUS -ne 0 ] && [ ! -s confirm_c3.bin ]; then
  echo "     - ${GREEN}PASS${NC} - cancelled run exited non-zero with no output"
else
  echo "     ! ${RED}FAIL${NC} - cancelled run must fail and emit nothing (exit $STATUS)"
  cat confirm_err.log
  exit 1
fi

if cmp -s .keychain/confirm1_enc.key confirm_key_before.snap &&
   cmp -s .keychain/confirm1.meta confirm_meta_before.snap; then
  echo "     - ${GREEN}PASS${NC} - key file and metadata are byte-identical after cancel"
else
  echo "     ! ${RED}FAIL${NC} - cancel must not touch key material or metadata"
  exit 1
fi

LEFTOVER=$(ls .keychain/confirm1_enc_pending* 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEFTOVER" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - no pending artifact or staging file left behind"
else
  echo "     ! ${RED}FAIL${NC} - cancel left staged files in .keychain/"
  ls .keychain/
  exit 1
fi

# -----------------------------------------------------------------------------
#  with no terminal and no -y the gate must fail closed, not assume yes -
#  unattended contexts are exactly where replayed/reordered input happens
# -----------------------------------------------------------------------------

echo "     Testing no terminal and no -y fails closed..."

OTP_TEST_NO_TTY=1 ./bin/otp -c confirm1 --encrypt < confirm_plain3.txt > confirm_c3.bin 2>confirm_err.log
STATUS=$?
if [ $STATUS -ne 0 ] && [ ! -s confirm_c3.bin ] &&
   grep -q "assume-delivered" confirm_err.log &&
   cmp -s .keychain/confirm1_enc.key confirm_key_before.snap; then
  echo "     - ${GREEN}PASS${NC} - refused without a terminal, keys intact, remedy named"
else
  echo "     ! ${RED}FAIL${NC} - must fail closed without a terminal (exit $STATUS)"
  cat confirm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  -y / --assume-delivered and OTP_ASSUME_DELIVERED=1 must each skip the
#  prompt entirely, including with no terminal available
# -----------------------------------------------------------------------------

echo "     Testing -y, --assume-delivered and OTP_ASSUME_DELIVERED bypasses..."

OTP_TEST_NO_TTY=1 ./bin/otp -c confirm1 --encrypt -y < confirm_plain3.txt > confirm_c3.bin 2>confirm_err.log
if [ $? -eq 0 ] && [ -s confirm_c3.bin ] && ! grep -q "Confirmation required" confirm_err.log; then
  echo "     - ${GREEN}PASS${NC} - -y proceeds without prompting"
else
  echo "     ! ${RED}FAIL${NC} - -y must skip the prompt"
  cat confirm_err.log
  exit 1
fi

printf 'and another' > confirm_plain4.txt
OTP_TEST_NO_TTY=1 ./bin/otp -c confirm1 --encrypt --assume-delivered < confirm_plain4.txt > confirm_c4.bin 2>confirm_err.log
if [ $? -eq 0 ] && [ -s confirm_c4.bin ] && ! grep -q "Confirmation required" confirm_err.log; then
  echo "     - ${GREEN}PASS${NC} - --assume-delivered proceeds without prompting"
else
  echo "     ! ${RED}FAIL${NC} - --assume-delivered must skip the prompt"
  cat confirm_err.log
  exit 1
fi

printf 'one more' > confirm_plain5.txt
OTP_TEST_NO_TTY=1 OTP_ASSUME_DELIVERED=1 ./bin/otp -c confirm1 --encrypt < confirm_plain5.txt > confirm_c5.bin 2>confirm_err.log
if [ $? -eq 0 ] && [ -s confirm_c5.bin ] && ! grep -q "Confirmation required" confirm_err.log; then
  echo "     - ${GREEN}PASS${NC} - OTP_ASSUME_DELIVERED=1 proceeds without prompting"
else
  echo "     ! ${RED}FAIL${NC} - OTP_ASSUME_DELIVERED=1 must skip the prompt"
  cat confirm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  decrypt side: cancelling must lose nothing - the same ciphertext must
#  still decrypt correctly on a later, confirmed attempt
# -----------------------------------------------------------------------------

echo "     Testing decrypt-side cancel loses nothing..."

rm -rf .keychain
dd if=/dev/urandom of=confirm_key2.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=confirm_key2.txt.dec bs=1 count=1000 2>/dev/null
./bin/otp --add-contact confirm2 confirm_key2.txt confirm_key2.txt.dec > /dev/null 2>&1

printf 'incoming one' > confirm_din1.txt
printf 'incoming two' > confirm_din2.txt
confirm_cipher confirm_key2.txt.dec confirm_din1.txt 0 confirm_dc1.bin
confirm_cipher confirm_key2.txt.dec confirm_din2.txt 12 confirm_dc2.bin

# first incoming message: no prompt needed
OTP_TEST_NO_TTY=1 ./bin/otp -c confirm2 --decrypt < confirm_dc1.bin > confirm_dout1.txt 2>confirm_err.log
if [ $? -eq 0 ] && cmp -s confirm_dout1.txt confirm_din1.txt; then
  echo "     - ${GREEN}PASS${NC} - first incoming message decrypted without prompting"
else
  echo "     ! ${RED}FAIL${NC} - first decrypt failed"
  cat confirm_err.log
  exit 1
fi

# second incoming message, operator answers no: cancelled, key intact
cp .keychain/confirm2_dec.key confirm_deckey.snap
OTP_TEST_CONFIRM_ANSWER=n ./bin/otp -c confirm2 --decrypt < confirm_dc2.bin > confirm_dout2.txt 2>confirm_err.log
if [ $? -ne 0 ] && [ ! -s confirm_dout2.txt ] &&
   cmp -s .keychain/confirm2_dec.key confirm_deckey.snap; then
  echo "     - ${GREEN}PASS${NC} - decrypt cancelled on 'n', decryption key intact"
else
  echo "     ! ${RED}FAIL${NC} - decrypt cancel must consume no key and emit nothing"
  cat confirm_err.log
  exit 1
fi

# the very same ciphertext must still decrypt after a confirmed retry
# ("yes" spelled out, to cover that accepted answer too)
OTP_TEST_CONFIRM_ANSWER=yes ./bin/otp -c confirm2 --decrypt < confirm_dc2.bin > confirm_dout2.txt 2>confirm_err.log
if [ $? -eq 0 ] && cmp -s confirm_dout2.txt confirm_din2.txt; then
  echo "     - ${GREEN}PASS${NC} - same ciphertext decrypts correctly after confirmed retry"
else
  echo "     ! ${RED}FAIL${NC} - cancelled decrypt must remain retryable"
  cat confirm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  recovery redelivery must NOT prompt: it re-emits already-committed
#  output and consumes no new key, so there is nothing to confirm - and
#  gating it would deadlock unattended crash recovery
# -----------------------------------------------------------------------------

echo "     Testing crash-recovery redelivery skips the prompt..."

rm -rf .keychain
dd if=/dev/urandom of=confirm_key3.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=confirm_key3.txt.dec bs=1 count=1000 2>/dev/null
./bin/otp --add-contact confirm3 confirm_key3.txt confirm_key3.txt.dec > /dev/null 2>&1

printf 'committed but undelivered' > confirm_plain6.txt
confirm_cipher confirm_key3.txt confirm_plain6.txt 0 confirm_expected6.bin

OTP_ASSUME_DELIVERED=1 OTP_TEST_CRASH_POINT=after_keychain_save \
  ./bin/otp -c confirm3 --encrypt < confirm_plain6.txt > /dev/null 2>/dev/null

printf 'new input, must be ignored' | OTP_TEST_NO_TTY=1 \
  ./bin/otp -c confirm3 --encrypt > confirm_redelivered.bin 2>confirm_err.log
STATUS=$?
if [ $STATUS -eq 3 ] && cmp -s confirm_redelivered.bin confirm_expected6.bin &&
   ! grep -q "Confirmation required" confirm_err.log; then
  echo "     - ${GREEN}PASS${NC} - redelivery ran unprompted with no terminal and exited 3"
else
  echo "     ! ${RED}FAIL${NC} - redelivery must not be gated (exit $STATUS)"
  cat confirm_err.log
  exit 1
fi

echo "     Cleaning up test files..."
rm -f confirm_key1.txt confirm_key1.txt.dec confirm_key2.txt confirm_key2.txt.dec \
      confirm_key3.txt confirm_key3.txt.dec confirm_plain1.txt confirm_plain2.txt \
      confirm_plain3.txt confirm_plain4.txt confirm_plain5.txt confirm_plain6.txt \
      confirm_c1.bin confirm_c2.bin confirm_c3.bin confirm_c4.bin confirm_c5.bin \
      confirm_din1.txt confirm_din2.txt confirm_dc1.bin confirm_dc2.bin \
      confirm_dout1.txt confirm_dout2.txt confirm_expected6.bin confirm_redelivered.bin \
      confirm_err.log confirm_key_before.snap confirm_meta_before.snap confirm_deckey.snap
rm -rf .keychain
