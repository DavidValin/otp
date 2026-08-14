#!/bin/sh

# Crash-safety / atomic-commit tests for the encrypt/decrypt key-consumption
# mechanism implemented in src/commit.c.
#
# These tests use the OTP_TEST_CRASH_POINT environment variable - a
# test-only hook compiled into the binary (see commit_test_crash_point() in
# src/commit.c) - to deterministically simulate a process crash at each of
# the three points where an interrupted commit can leave state in a
# distinct, recoverable configuration. See the "Crash-safe key consumption"
# section of README.md for the full design and the recovery truth table
# this verifies.

rm -f keychain.txt
rm -rf .keychain

echo ""
echo "   - Commit / crash-recovery functionality"

# -----------------------------------------------------------------------------
#  helper: compute the expected ciphertext for the first N bytes of a key
#  file, where N is the size of the given plaintext file
# -----------------------------------------------------------------------------
expected_cipher() {
  KEYFILE=$1
  PLAINFILE=$2
  OFF=$3
  OUT=$4
  LEN=$(wc -c < "$PLAINFILE" | tr -d ' ')
  dd if="$KEYFILE" of=commit_key_slice.tmp bs=1 skip="$OFF" count="$LEN" 2>/dev/null
  ./bin/otp commit_key_slice.tmp < "$PLAINFILE" > "$OUT" 2>/dev/null
  rm -f commit_key_slice.tmp commit_key_slice.tmp.*.next
}

# -----------------------------------------------------------------------------
#  window 1: crash before the key file or the contact's metadata file are ever touched
#  (only the pending artifact was published) -> discarded safely on the
#  next run, no key wasted, new input still processed normally
# -----------------------------------------------------------------------------

echo "     Testing recovery window 1 (crash before any commit)..."

dd if=/dev/urandom of=commit_key1.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact committest1 commit_key1.txt commit_key1.txt > /dev/null 2>&1

printf 'hello window one' > commit_plain1.txt
OTP_TEST_CRASH_POINT=after_pending_publish ./bin/otp -c committest1 --encrypt < commit_plain1.txt > /dev/null 2>commit_stderr1.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - PASS - simulated crash landed at the intended point"
else
  echo "     ! FAIL - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest1_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "1" ]; then
  echo "     - PASS - pending artifact was staged before the simulated crash"
else
  echo "     ! FAIL - expected exactly one pending artifact, found $PENDING_COUNT"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest1)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 0")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: 0")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - PASS - key state untouched after crash before any commit"
else
  echo "     ! FAIL - key state changed despite crash before any commit"
  exit 1
fi

# Recovery on the next run must discard the stale pending artifact and
# still process the new input normally.
printf 'brand new real message' > commit_plain2.txt
./bin/otp -c committest1 --encrypt < commit_plain2.txt > commit_cipher2.bin 2>commit_stderr2.log

grep -q "discarded an uncommitted pending encryption" commit_stderr2.log
if [ $? -eq 0 ]; then
  echo "     - PASS - stale pending artifact reported as discarded"
else
  echo "     ! FAIL - discard was not reported to the user"
  cat commit_stderr2.log
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest1_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - PASS - stale pending artifact removed"
else
  echo "     ! FAIL - stale pending artifact still present"
  exit 1
fi

expected_cipher commit_key1.txt commit_plain2.txt 0 commit_expected2.bin
cmp -s commit_cipher2.bin commit_expected2.bin
if [ $? -eq 0 ]; then
  echo "     - PASS - new message encrypted from the key's true start (nothing wasted or reused)"
else
  echo "     ! FAIL - new message was not encrypted with the expected key bytes"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest1)
echo "$OUTPUT" | grep -q "EncryptedSequence: 1"
if [ $? -eq 0 ]; then
  echo "     - PASS - sequence advanced exactly once for the one real message"
else
  echo "     ! FAIL - sequence did not advance correctly"
  exit 1
fi

rm -f commit_key1.txt commit_plain1.txt commit_plain2.txt commit_cipher2.bin commit_expected2.bin
rm -f commit_stderr1.log commit_stderr2.log
rm -f keychain.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  window 2: crash between the key file commit and the metadata commit
#  (key file already truncated, .meta file still stale) -> the next run
#  must deterministically finish the commit using the pending artifact's
#  own filename tag, then redeliver the original ciphertext
# -----------------------------------------------------------------------------

echo "     Testing recovery window 2 (crash between key-file and metadata commit)..."

dd if=/dev/urandom of=commit_key2.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact committest2 commit_key2.txt commit_key2.txt > /dev/null 2>&1

printf 'window two message content' > commit_plainA.txt
OTP_TEST_CRASH_POINT=after_key_publish ./bin/otp -c committest2 --encrypt < commit_plainA.txt > /dev/null 2>commit_stderrA.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - PASS - simulated crash landed after the key file commit"
else
  echo "     ! FAIL - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest2)
echo "$OUTPUT" | grep -q "EncryptedSequence: 0"
if [ $? -eq 0 ]; then
  echo "     - PASS - metadata file is stale as expected (sequence not yet advanced)"
else
  echo "     ! FAIL - metadata file should still show the pre-crash sequence"
  exit 1
fi

MSGLEN=$(wc -c < commit_plainA.txt | tr -d ' ')
ACTUAL_KEY_SIZE=$(wc -c < .keychain/committest2_enc.key | tr -d ' ')
EXPECTED_REMAINING=$((1000 - MSGLEN))
if [ "$ACTUAL_KEY_SIZE" = "$EXPECTED_REMAINING" ]; then
  echo "     - PASS - key file already truncated on disk despite stale metadata"
else
  echo "     ! FAIL - key file truncation state unexpected ($ACTUAL_KEY_SIZE vs $EXPECTED_REMAINING)"
  exit 1
fi

expected_cipher commit_key2.txt commit_plainA.txt 0 commit_expectedA.bin

# Feed different new input to prove it is ignored: only the recovered
# message should ever be redelivered during recovery.
printf 'this should be ignored during recovery' | ./bin/otp -c committest2 --encrypt > commit_recoveredA.bin 2>commit_stderrB.log

grep -q "Recovered incomplete delivery" commit_stderrB.log
if [ $? -eq 0 ]; then
  echo "     - PASS - recovery reported to the user"
else
  echo "     ! FAIL - recovery was not reported"
  cat commit_stderrB.log
  exit 1
fi

cmp -s commit_recoveredA.bin commit_expectedA.bin
if [ $? -eq 0 ]; then
  echo "     - PASS - redelivered ciphertext matches the original message exactly"
else
  echo "     ! FAIL - redelivered ciphertext does not match"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest2)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - PASS - metadata commit was finished correctly by recovery"
else
  echo "     ! FAIL - metadata was not finished correctly by recovery"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest2_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - PASS - pending artifact cleaned up after redelivery"
else
  echo "     ! FAIL - pending artifact left behind after redelivery"
  exit 1
fi

# Normal operation must resume correctly afterwards, continuing from the
# now-correct offset.
printf 'real new message after recovery' > commit_plainB.txt
./bin/otp -c committest2 --encrypt < commit_plainB.txt > commit_cipherB.bin 2>/dev/null
expected_cipher commit_key2.txt commit_plainB.txt "$MSGLEN" commit_expectedB.bin
cmp -s commit_cipherB.bin commit_expectedB.bin
if [ $? -eq 0 ]; then
  echo "     - PASS - normal encryption resumed correctly after recovery"
else
  echo "     ! FAIL - encryption after recovery used the wrong key range"
  exit 1
fi

rm -f commit_key2.txt commit_plainA.txt commit_plainB.txt commit_expectedA.bin commit_expectedB.bin
rm -f commit_recoveredA.bin commit_cipherB.bin commit_stderrA.log commit_stderrB.log
rm -f keychain.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  window 3: crash after the full commit, before delivery/cleanup -> the
#  next run must redeliver the pending artifact without touching key state
#  a second time
# -----------------------------------------------------------------------------

echo "     Testing recovery window 3 (crash after full commit, before delivery)..."

dd if=/dev/urandom of=commit_key3.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact committest3 commit_key3.txt commit_key3.txt > /dev/null 2>&1

printf 'window three message' > commit_plainC.txt
OTP_TEST_CRASH_POINT=after_keychain_save ./bin/otp -c committest3 --encrypt < commit_plainC.txt > /dev/null 2>commit_stderrC.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - PASS - simulated crash landed after the full commit"
else
  echo "     ! FAIL - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

MSGLEN=$(wc -c < commit_plainC.txt | tr -d ' ')
OUTPUT=$(./bin/otp --show-contact committest3)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - PASS - key state was already fully committed before the simulated crash"
else
  echo "     ! FAIL - key state should already be fully committed at this crash point"
  exit 1
fi

expected_cipher commit_key3.txt commit_plainC.txt 0 commit_expectedC.bin

printf 'ignored input' | ./bin/otp -c committest3 --encrypt > commit_recoveredC.bin 2>commit_stderrD.log
grep -q "Recovered incomplete delivery" commit_stderrD.log
if [ $? -eq 0 ]; then
  echo "     - PASS - recovery reported to the user"
else
  echo "     ! FAIL - recovery was not reported"
  exit 1
fi

cmp -s commit_recoveredC.bin commit_expectedC.bin
if [ $? -eq 0 ]; then
  echo "     - PASS - redelivered ciphertext matches the original message exactly"
else
  echo "     ! FAIL - redelivered ciphertext does not match"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest3)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - PASS - redelivery did not double-consume key material"
else
  echo "     ! FAIL - redelivery incorrectly changed key state again"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest3_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - PASS - pending artifact cleaned up after redelivery"
else
  echo "     ! FAIL - pending artifact left behind"
  exit 1
fi

rm -f commit_key3.txt commit_plainC.txt commit_expectedC.bin commit_recoveredC.bin
rm -f commit_stderrC.log commit_stderrD.log
rm -f keychain.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  decrypt side: the same crash (window 2) must not permanently lose a
#  message - this is the case that matters most for decrypt, since unlike
#  encrypt there is no way to re-derive lost plaintext once its key bytes
#  are gone
# -----------------------------------------------------------------------------

echo "     Testing crash recovery on the decrypt side (no message loss)..."

dd if=/dev/urandom of=commit_deckey.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact decrecover commit_deckey.txt commit_deckey.txt > /dev/null 2>&1

printf 'secret plaintext for decrypt recovery' > commit_decplain.txt
./bin/otp -c decrecover --encrypt < commit_decplain.txt > commit_deccipher.bin 2>/dev/null

OTP_TEST_CRASH_POINT=after_key_publish ./bin/otp -c decrecover --decrypt < commit_deccipher.bin > /dev/null 2>commit_decstderr.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - PASS - simulated crash landed during decrypt commit"
else
  echo "     ! FAIL - simulated crash did not trigger as expected on decrypt (exit $RC)"
  exit 1
fi

printf 'ignored' | ./bin/otp -c decrecover --decrypt > commit_decrecovered.bin 2>commit_decstderr2.log
grep -q "Recovered incomplete delivery" commit_decstderr2.log
if [ $? -eq 0 ]; then
  echo "     - PASS - decrypt recovery reported to the user"
else
  echo "     ! FAIL - decrypt recovery was not reported"
  cat commit_decstderr2.log
  exit 1
fi

cmp -s commit_decrecovered.bin commit_decplain.txt
if [ $? -eq 0 ]; then
  echo "     - PASS - recovered plaintext matches the original message exactly (no data loss)"
else
  echo "     ! FAIL - recovered plaintext does not match - message would have been permanently lost"
  exit 1
fi

rm -f commit_deckey.txt commit_decplain.txt commit_deccipher.bin commit_decrecovered.bin
rm -f commit_decstderr.log commit_decstderr2.log

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -f keychain.txt
rm -rf .keychain

echo ""
exit 0
