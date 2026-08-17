#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# These tests exercise machinery other than the delivery-confirmation gate
# (see test/confirm.test.sh for that), so state the confirmation explicitly:
# without it, every message after a direction's first would prompt on the
# terminal - or fail closed when the test runs without one.
OTP_ASSUME_DELIVERED=1
export OTP_ASSUME_DELIVERED

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
dd if=/dev/urandom of=commit_key1.txt.dec bs=1 count=$(wc -c < commit_key1.txt) 2>/dev/null
./bin/otp --add-contact committest1 commit_key1.txt commit_key1.txt.dec > /dev/null 2>&1

printf 'hello window one' > commit_plain1.txt
OTP_TEST_CRASH_POINT=after_pending_publish ./bin/otp -c committest1 --encrypt < commit_plain1.txt > /dev/null 2>commit_stderr1.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - ${GREEN}PASS${NC} - simulated crash landed at the intended point"
else
  echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest1_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - pending artifact was staged before the simulated crash"
else
  echo "     ! ${RED}FAIL${NC} - expected exactly one pending artifact, found $PENDING_COUNT"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest1)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 0")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: 0")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - key state untouched after crash before any commit"
else
  echo "     ! ${RED}FAIL${NC} - key state changed despite crash before any commit"
  exit 1
fi

# Recovery on the next run must discard the stale pending artifact and
# still process the new input normally.
printf 'brand new real message' > commit_plain2.txt
./bin/otp -c committest1 --encrypt < commit_plain2.txt > commit_cipher2.bin 2>commit_stderr2.log

grep -q "discarded an uncommitted pending encryption" commit_stderr2.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - stale pending artifact reported as discarded"
else
  echo "     ! ${RED}FAIL${NC} - discard was not reported to the user"
  cat commit_stderr2.log
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest1_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - stale pending artifact removed"
else
  echo "     ! ${RED}FAIL${NC} - stale pending artifact still present"
  exit 1
fi

expected_cipher commit_key1.txt commit_plain2.txt 0 commit_expected2.bin
cmp -s commit_cipher2.bin commit_expected2.bin
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - new message encrypted from the key's true start (nothing wasted or reused)"
else
  echo "     ! ${RED}FAIL${NC} - new message was not encrypted with the expected key bytes"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest1)
echo "$OUTPUT" | grep -q "EncryptedSequence: 1"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - sequence advanced exactly once for the one real message"
else
  echo "     ! ${RED}FAIL${NC} - sequence did not advance correctly"
  exit 1
fi

rm -f commit_key1.txt commit_plain1.txt commit_plain2.txt commit_cipher2.bin commit_expected2.bin
rm -f commit_stderr1.log commit_stderr2.log
rm -rf .keychain

# -----------------------------------------------------------------------------
#  window 2: crash between the key file commit and the metadata commit
#  (key file already truncated, .meta file still stale) -> the next run
#  must deterministically finish the commit using the pending artifact's
#  own filename tag, then redeliver the original ciphertext
# -----------------------------------------------------------------------------

echo "     Testing recovery window 2 (crash between key-file and metadata commit)..."

dd if=/dev/urandom of=commit_key2.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_key2.txt.dec bs=1 count=$(wc -c < commit_key2.txt) 2>/dev/null
./bin/otp --add-contact committest2 commit_key2.txt commit_key2.txt.dec > /dev/null 2>&1

printf 'window two message content' > commit_plainA.txt
OTP_TEST_CRASH_POINT=after_key_publish ./bin/otp -c committest2 --encrypt < commit_plainA.txt > /dev/null 2>commit_stderrA.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - ${GREEN}PASS${NC} - simulated crash landed after the key file commit"
else
  echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest2)
echo "$OUTPUT" | grep -q "EncryptedSequence: 0"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - metadata file is stale as expected (sequence not yet advanced)"
else
  echo "     ! ${RED}FAIL${NC} - metadata file should still show the pre-crash sequence"
  exit 1
fi

MSGLEN=$(wc -c < commit_plainA.txt | tr -d ' ')
ACTUAL_KEY_SIZE=$(wc -c < .keychain/committest2_enc.key | tr -d ' ')
EXPECTED_REMAINING=$((1000 - MSGLEN))
if [ "$ACTUAL_KEY_SIZE" = "$EXPECTED_REMAINING" ]; then
  echo "     - ${GREEN}PASS${NC} - key file already truncated on disk despite stale metadata"
else
  echo "     ! ${RED}FAIL${NC} - key file truncation state unexpected ($ACTUAL_KEY_SIZE vs $EXPECTED_REMAINING)"
  exit 1
fi

expected_cipher commit_key2.txt commit_plainA.txt 0 commit_expectedA.bin

# Feed different new input to prove it is ignored: only the recovered
# message should ever be redelivered during recovery.
printf 'this should be ignored during recovery' | ./bin/otp -c committest2 --encrypt > commit_recoveredA.bin 2>commit_stderrB.log

grep -q "Recovered incomplete delivery" commit_stderrB.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - recovery reported to the user"
else
  echo "     ! ${RED}FAIL${NC} - recovery was not reported"
  cat commit_stderrB.log
  exit 1
fi

cmp -s commit_recoveredA.bin commit_expectedA.bin
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - redelivered ciphertext matches the original message exactly"
else
  echo "     ! ${RED}FAIL${NC} - redelivered ciphertext does not match"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest2)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - metadata commit was finished correctly by recovery"
else
  echo "     ! ${RED}FAIL${NC} - metadata was not finished correctly by recovery"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest2_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - pending artifact cleaned up after redelivery"
else
  echo "     ! ${RED}FAIL${NC} - pending artifact left behind after redelivery"
  exit 1
fi

# Normal operation must resume correctly afterwards, continuing from the
# now-correct offset.
printf 'real new message after recovery' > commit_plainB.txt
./bin/otp -c committest2 --encrypt < commit_plainB.txt > commit_cipherB.bin 2>/dev/null
expected_cipher commit_key2.txt commit_plainB.txt "$MSGLEN" commit_expectedB.bin
cmp -s commit_cipherB.bin commit_expectedB.bin
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - normal encryption resumed correctly after recovery"
else
  echo "     ! ${RED}FAIL${NC} - encryption after recovery used the wrong key range"
  exit 1
fi

rm -f commit_key2.txt commit_plainA.txt commit_plainB.txt commit_expectedA.bin commit_expectedB.bin
rm -f commit_recoveredA.bin commit_cipherB.bin commit_stderrA.log commit_stderrB.log
rm -rf .keychain

# -----------------------------------------------------------------------------
#  window 3: crash after the full commit, before delivery/cleanup -> the
#  next run must redeliver the pending artifact without touching key state
#  a second time
# -----------------------------------------------------------------------------

echo "     Testing recovery window 3 (crash after full commit, before delivery)..."

dd if=/dev/urandom of=commit_key3.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_key3.txt.dec bs=1 count=$(wc -c < commit_key3.txt) 2>/dev/null
./bin/otp --add-contact committest3 commit_key3.txt commit_key3.txt.dec > /dev/null 2>&1

printf 'window three message' > commit_plainC.txt
OTP_TEST_CRASH_POINT=after_keychain_save ./bin/otp -c committest3 --encrypt < commit_plainC.txt > /dev/null 2>commit_stderrC.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - ${GREEN}PASS${NC} - simulated crash landed after the full commit"
else
  echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected (exit $RC)"
  exit 1
fi

MSGLEN=$(wc -c < commit_plainC.txt | tr -d ' ')
OUTPUT=$(./bin/otp --show-contact committest3)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - key state was already fully committed before the simulated crash"
else
  echo "     ! ${RED}FAIL${NC} - key state should already be fully committed at this crash point"
  exit 1
fi

expected_cipher commit_key3.txt commit_plainC.txt 0 commit_expectedC.bin

printf 'ignored input' | ./bin/otp -c committest3 --encrypt > commit_recoveredC.bin 2>commit_stderrD.log
grep -q "Recovered incomplete delivery" commit_stderrD.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - recovery reported to the user"
else
  echo "     ! ${RED}FAIL${NC} - recovery was not reported"
  exit 1
fi

cmp -s commit_recoveredC.bin commit_expectedC.bin
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - redelivered ciphertext matches the original message exactly"
else
  echo "     ! ${RED}FAIL${NC} - redelivered ciphertext does not match"
  exit 1
fi

OUTPUT=$(./bin/otp --show-contact committest3)
SEQ_OK=$(echo "$OUTPUT" | grep -c "EncryptedSequence: 1")
OFF_OK=$(echo "$OUTPUT" | grep -c "EncryptionKeyOffset: $MSGLEN")
if [ "$SEQ_OK" = "1" ] && [ "$OFF_OK" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - redelivery did not double-consume key material"
else
  echo "     ! ${RED}FAIL${NC} - redelivery incorrectly changed key state again"
  exit 1
fi

PENDING_COUNT=$(ls .keychain/committest3_enc_pending_* 2>/dev/null | wc -l)
if [ "$PENDING_COUNT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - pending artifact cleaned up after redelivery"
else
  echo "     ! ${RED}FAIL${NC} - pending artifact left behind"
  exit 1
fi

rm -f commit_key3.txt commit_plainC.txt commit_expectedC.bin commit_recoveredC.bin
rm -f commit_stderrC.log commit_stderrD.log
rm -rf .keychain

# -----------------------------------------------------------------------------
#  decrypt side: the same crash (window 2) must not permanently lose a
#  message - this is the case that matters most for decrypt, since unlike
#  encrypt there is no way to re-derive lost plaintext once its key bytes
#  are gone
# -----------------------------------------------------------------------------

echo "     Testing crash recovery on the decrypt side (no message loss)..."

dd if=/dev/urandom of=commit_deckey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_deckey.txt.dec bs=1 count=$(wc -c < commit_deckey.txt) 2>/dev/null
./bin/otp --add-contact decrecover commit_deckey.txt commit_deckey.txt.dec > /dev/null 2>&1

printf 'secret plaintext for decrypt recovery' > commit_decplain.txt
# The peer encrypts with what is our DECRYPTION key, so build the incoming
# ciphertext from that file rather than by encrypting with this contact.
expected_cipher commit_deckey.txt.dec commit_decplain.txt 0 commit_deccipher.bin

OTP_TEST_CRASH_POINT=after_key_publish ./bin/otp -c decrecover --decrypt < commit_deccipher.bin > /dev/null 2>commit_decstderr.log
RC=$?
if [ $RC -eq 77 ]; then
  echo "     - ${GREEN}PASS${NC} - simulated crash landed during decrypt commit"
else
  echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected on decrypt (exit $RC)"
  exit 1
fi

printf 'ignored' | ./bin/otp -c decrecover --decrypt > commit_decrecovered.bin 2>commit_decstderr2.log
grep -q "Recovered incomplete delivery" commit_decstderr2.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - decrypt recovery reported to the user"
else
  echo "     ! ${RED}FAIL${NC} - decrypt recovery was not reported"
  cat commit_decstderr2.log
  exit 1
fi

cmp -s commit_decrecovered.bin commit_decplain.txt
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - recovered plaintext matches the original message exactly (no data loss)"
else
  echo "     ! ${RED}FAIL${NC} - recovered plaintext does not match - message would have been permanently lost"
  exit 1
fi

rm -f commit_deckey.txt commit_decplain.txt commit_deccipher.bin commit_decrecovered.bin
rm -f commit_decstderr.log commit_decstderr2.log

# -----------------------------------------------------------------------------
#  a redelivered message must NOT report success
#
#  Recovery redelivers the previous run's output and leaves this run's
#  input entirely unprocessed. Exiting 0 there would let a script believe
#  its message had been encrypted when the bytes it got back belong to a
#  different message. It gets its own exit code (KEYCHAIN_REDELIVERED = 3).
# -----------------------------------------------------------------------------

echo "     Testing that a redelivery is not reported as success..."

dd if=/dev/urandom of=commit_rdkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_rdkey.txt.dec bs=1 count=$(wc -c < commit_rdkey.txt) 2>/dev/null
./bin/otp --add-contact redeliv commit_rdkey.txt commit_rdkey.txt.dec > /dev/null 2>&1

printf 'first message' > commit_rdfirst.txt
OTP_TEST_CRASH_POINT=after_keychain_save ./bin/otp -c redeliv --encrypt \
  < commit_rdfirst.txt > /dev/null 2>/dev/null

printf 'second message, must not be silently dropped' > commit_rdsecond.txt
./bin/otp -c redeliv --encrypt < commit_rdsecond.txt > commit_rdout.bin 2>/dev/null
RC=$?

if [ $RC -eq 3 ]; then
  echo "     - ${GREEN}PASS${NC} - redelivery exits 3, distinguishable from success"
else
  echo "     ! ${RED}FAIL${NC} - redelivery exited $RC (expected 3)"
  exit 1
fi

# ...and re-running must then encrypt the input that was skipped
./bin/otp -c redeliv --encrypt < commit_rdsecond.txt > commit_rdout2.bin 2>/dev/null
RC2=$?
OFF=$(grep '^EncryptionKeyOffset=' .keychain/redeliv.meta | cut -d= -f2)
LEN1=$(wc -c < commit_rdfirst.txt | tr -d ' ')
LEN2=$(wc -c < commit_rdsecond.txt | tr -d ' ')
EXPECTED_OFF=$((LEN1 + LEN2))

if [ $RC2 -eq 0 ] && [ "$OFF" = "$EXPECTED_OFF" ]; then
  echo "     - ${GREEN}PASS${NC} - re-running then processes the skipped input, consuming key exactly once"
else
  echo "     ! ${RED}FAIL${NC} - re-run exited $RC2 with offset $OFF (expected 0 and $EXPECTED_OFF)"
  exit 1
fi

rm -f commit_rdkey.txt commit_rdfirst.txt commit_rdsecond.txt commit_rdout.bin commit_rdout2.bin

# -----------------------------------------------------------------------------
#  abandoned staging files must be swept away
#
#  A process killed while still writing its output leaves a partial
#  staging file. It is unverified and unpublished, so it carries no
#  recoverable meaning - but on the decrypt side it holds recovered
#  plaintext, so it must not survive on disk.
# -----------------------------------------------------------------------------

echo "     Testing that abandoned staging files are swept away..."

dd if=/dev/urandom of=commit_stagekey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_stagekey.txt.dec bs=1 count=$(wc -c < commit_stagekey.txt) 2>/dev/null
./bin/otp --add-contact staged commit_stagekey.txt commit_stagekey.txt.dec > /dev/null 2>&1

# Plant staging files of the exact shape a killed process leaves behind
printf 'leftover ciphertext bytes' > .keychain/staged_enc_pending.99999.tmp
printf 'leftover PLAINTEXT bytes' > .keychain/staged_dec_pending.99999.tmp
printf 'leftover KEY MATERIAL' > .keychain/staged_enc.key.tmp
printf 'leftover metadata' > .keychain/staged.meta.tmp

printf 'a message' | ./bin/otp -c staged --encrypt > commit_stageout.bin 2>/dev/null
RC=$?

if [ $RC -eq 0 ] && [ ! -f ".keychain/staged_enc_pending.99999.tmp" ]; then
  echo "     - ${GREEN}PASS${NC} - a stale encrypt staging file is swept on the next operation"
else
  echo "     ! ${RED}FAIL${NC} - stale encrypt staging file survived (exit $RC)"
  ls .keychain/
  exit 1
fi

# The decrypt-side one belongs to the other direction, so it survives an
# encrypt - but removing the contact must take everything with it
if [ -f ".keychain/staged_dec_pending.99999.tmp" ]; then
  echo "     - ${GREEN}PASS${NC} - the other direction's staging file is left for that direction to sweep"
else
  echo "     ! ${RED}FAIL${NC} - encrypt swept a decrypt staging file it does not own"
  exit 1
fi

# Removing the contact must take every trace of message content with it.
# The empty <contact>.lock file is the one deliberate exception: unlinking
# it would let a process already blocked on it and a later process that
# recreates the path both believe they hold the lock.
./bin/otp --remove-contact staged > /dev/null 2>&1
LEFTOVER=$(ls .keychain/ 2>/dev/null | grep "^staged" | grep -vc "^staged\.lock$")
if [ "$LEFTOVER" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - removing a contact leaves none of its staged content behind"
else
  echo "     ! ${RED}FAIL${NC} - removing the contact left $LEFTOVER file(s) behind"
  ls .keychain/
  exit 1
fi

rm -f commit_stagekey.txt commit_stageout.bin

# -----------------------------------------------------------------------------
#  metadata that has drifted from the key file must self-heal
#
#  The key file is the authority on how much key remains: bytes are
#  consumed from the front and it is physically truncated. Metadata that
#  overstates the remaining length used to make every later operation fail
#  forever, with no way back short of hand-editing the .meta file.
# -----------------------------------------------------------------------------

echo "     Testing that metadata drifted from the key file self-heals..."

dd if=/dev/urandom of=commit_healkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_healkey.txt.dec bs=1 count=$(wc -c < commit_healkey.txt) 2>/dev/null
./bin/otp --add-contact healed commit_healkey.txt commit_healkey.txt.dec > /dev/null 2>&1

# Overstate the remaining key: claim 1000 bytes when the file holds 1000
# but pretend 200 have not been consumed yet by shrinking the real file
dd if=commit_healkey.txt of=.keychain/healed_enc.key bs=1 count=800 2>/dev/null

printf 'heal me' | ./bin/otp -c healed --encrypt > commit_healout.bin 2>commit_healstderr.log
RC=$?

if [ $RC -eq 0 ] && [ -s commit_healout.bin ]; then
  echo "     - ${GREEN}PASS${NC} - an overstated key size is corrected instead of failing forever"
else
  echo "     ! ${RED}FAIL${NC} - drifted metadata left the contact unusable (exit $RC)"
  cat commit_healstderr.log
  exit 1
fi

grep -q "adopting the key file's size" commit_healstderr.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the correction is reported rather than made silently"
else
  echo "     ! ${RED}FAIL${NC} - the metadata correction was not reported"
  cat commit_healstderr.log
  exit 1
fi

SIZE=$(grep '^EncryptionKeySize=' .keychain/healed.meta | cut -d= -f2)
ACTUAL=$(wc -c < .keychain/healed_enc.key | tr -d ' ')
if [ "$SIZE" = "$ACTUAL" ]; then
  echo "     - ${GREEN}PASS${NC} - metadata now agrees with the key file ($SIZE bytes)"
else
  echo "     ! ${RED}FAIL${NC} - metadata says $SIZE, key file holds $ACTUAL"
  exit 1
fi

# The opposite drift - a key file LARGER than metadata claims - means key
# material was restored from an older copy, and continuing would reuse
# bytes that were already spent. That must be refused, never "healed".
cat commit_healkey.txt > .keychain/healed_enc.key

printf 'should be refused' | ./bin/otp -c healed --encrypt > commit_healout2.bin 2>commit_healstderr2.log
RC=$?
if [ $RC -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - a rolled-back (larger) key file is refused, not adopted"
else
  echo "     ! ${RED}FAIL${NC} - a rolled-back key file was accepted - key material could be reused"
  exit 1
fi

grep -q "restored or rolled back" commit_healstderr2.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal explains that key material was rolled back"
else
  echo "     ! ${RED}FAIL${NC} - the refusal did not explain why"
  cat commit_healstderr2.log
  exit 1
fi

rm -f commit_healkey.txt commit_healout.bin commit_healout2.bin
rm -f commit_healstderr.log commit_healstderr2.log

# -----------------------------------------------------------------------------
#  a delivery that fails must not be reported as success
#
#  fwrite() only fills the stdio buffer; a message smaller than that
#  buffer has not reached the OS when delivery returns. If success is
#  declared without flushing, the caller deletes the verified copy and the
#  message is gone with its key already spent - on the decrypt side,
#  unrecoverably. /dev/full makes every write fail with ENOSPC.
# -----------------------------------------------------------------------------

if [ -w /dev/full ]; then
  echo "     Testing that a failed delivery is detected and recoverable..."

  dd if=/dev/urandom of=commit_fullkey.txt bs=1 count=1000 2>/dev/null
  dd if=/dev/urandom of=commit_fullkey.txt.dec bs=1 count=$(wc -c < commit_fullkey.txt) 2>/dev/null
  ./bin/otp --add-contact fulldisk commit_fullkey.txt commit_fullkey.txt.dec > /dev/null 2>&1

  printf 'this message must survive a full disk' > commit_fullmsg.txt
  ./bin/otp -c fulldisk --encrypt < commit_fullmsg.txt > /dev/full 2>commit_fullerr.log
  RC=$?

  if [ $RC -ne 0 ]; then
    echo "     - ${GREEN}PASS${NC} - delivery onto a full disk reports failure"
  else
    echo "     ! ${RED}FAIL${NC} - delivery onto a full disk reported success (exit $RC)"
    exit 1
  fi

  PENDING=$(ls .keychain/ 2>/dev/null | grep -c "fulldisk_enc_pending_seq")
  if [ "$PENDING" = "1" ]; then
    echo "     - ${GREEN}PASS${NC} - the verified copy is retained rather than deleted"
  else
    echo "     ! ${RED}FAIL${NC} - the verified copy was discarded after a failed delivery"
    ls .keychain/
    exit 1
  fi

  # The message must come back intact on the next run
  printf 'ignored' | ./bin/otp -c fulldisk --encrypt > commit_fullout.bin 2>/dev/null
  RC=$?
  expected_cipher commit_fullkey.txt commit_fullmsg.txt 0 commit_fullexp.bin
  cmp -s commit_fullout.bin commit_fullexp.bin
  CMP_RC=$?
  if [ $RC -eq 3 ] && [ $CMP_RC -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - the message is redelivered byte-exact on the next run"
  else
    echo "     ! ${RED}FAIL${NC} - message not recovered after the failed delivery (exit $RC)"
    exit 1
  fi

  ./bin/otp --remove-contact fulldisk > /dev/null 2>&1
  rm -f commit_fullkey.txt commit_fullmsg.txt commit_fullout.bin commit_fullexp.bin commit_fullerr.log
fi

# -----------------------------------------------------------------------------
#  a read error on the input must not be mistaken for end-of-input
#
#  fread() returns 0 for both. Treating an error as EOF would commit a
#  truncated prefix of the caller's message as though it were complete,
#  spending key material on it and reporting success.
# -----------------------------------------------------------------------------

echo "     Testing that an input read error is not mistaken for end-of-input..."

dd if=/dev/urandom of=commit_readkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_readkey.txt.dec bs=1 count=$(wc -c < commit_readkey.txt) 2>/dev/null
./bin/otp --add-contact readerr commit_readkey.txt commit_readkey.txt.dec > /dev/null 2>&1

mkdir -p commit_notafile
./bin/otp -c readerr --encrypt < commit_notafile > /dev/null 2>commit_readerr.log
RC=$?
OFFSET=$(grep '^EncryptionKeyOffset=' .keychain/readerr.meta | cut -d= -f2)

if [ $RC -ne 0 ] && [ "$OFFSET" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a failed read aborts without consuming key material"
else
  echo "     ! ${RED}FAIL${NC} - a failed read was treated as valid input (exit $RC, offset $OFFSET)"
  cat commit_readerr.log
  exit 1
fi

grep -q "Failed reading input" commit_readerr.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the read failure is reported as such"
else
  echo "     ! ${RED}FAIL${NC} - the read failure was not reported"
  cat commit_readerr.log
  exit 1
fi

./bin/otp --remove-contact readerr > /dev/null 2>&1
rmdir commit_notafile
rm -f commit_readkey.txt commit_readerr.log

# -----------------------------------------------------------------------------
#  the read-back verification must actually fire
#
#  Every staged write is fsynced, reopened and compared against what was
#  intended - a successful fwrite() only proves libc accepted the bytes.
#  Every test above confirms the protocol behaves when each step SUCCEEDS;
#  these two confirm the check itself catches a bad write, by corrupting
#  the staged file between the write and its verification.
# -----------------------------------------------------------------------------

echo "     Testing that staged-write verification catches corruption..."

dd if=/dev/urandom of=commit_vkey.txt bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=commit_vkey.txt.dec bs=1 count=$(wc -c < commit_vkey.txt) 2>/dev/null
./bin/otp --add-contact verifytest commit_vkey.txt commit_vkey.txt.dec > /dev/null 2>&1

# 1. the streamed ciphertext (CRC32 check in commit_stage_close_verified)
printf 'this staged output gets corrupted' | \
  OTP_TEST_CORRUPT_POINT=staged_output ./bin/otp -c verifytest --encrypt > /dev/null 2>commit_verr1.log
RC=$?
OFF=$(grep '^EncryptionKeyOffset=' .keychain/verifytest.meta | cut -d= -f2)
PEND=$(ls .keychain/ 2>/dev/null | grep -c "verifytest_enc_pending")

if [ $RC -ne 0 ] && [ "$OFF" = "0" ] && [ "$PEND" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a corrupted staged ciphertext is detected, nothing committed"
else
  echo "     ! ${RED}FAIL${NC} - corrupted staged ciphertext slipped through (exit $RC, offset $OFF, $PEND pending)"
  cat commit_verr1.log
  exit 1
fi

grep -q "verification failed for staged file" commit_verr1.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the failure names the staged file that failed verification"
else
  echo "     ! ${RED}FAIL${NC} - verification failure not reported"
  cat commit_verr1.log
  exit 1
fi

# 2. the metadata file (byte-for-byte check in commit_write_verified)
printf 'this run corrupts the staged metadata' | \
  OTP_TEST_CORRUPT_POINT=verified_write ./bin/otp -c verifytest --encrypt > /dev/null 2>commit_verr2.log
RC=$?
grep -q "verification failed for .keychain/verifytest.meta.tmp" commit_verr2.log
GREP_RC=$?

if [ $RC -ne 0 ] && [ $GREP_RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - a corrupted staged .meta is detected before it is published"
else
  echo "     ! ${RED}FAIL${NC} - corrupted staged .meta slipped through (exit $RC)"
  cat commit_verr2.log
  exit 1
fi

# That run got as far as truncating the key, so it left a recoverable
# window-2 state. Draining it also re-proves recovery after this failure.
printf 'drain' | ./bin/otp -c verifytest --encrypt > /dev/null 2>&1

rm -f commit_vkey.txt commit_verr1.log commit_verr2.log
./bin/otp --remove-contact verifytest > /dev/null 2>&1

# -----------------------------------------------------------------------------
#  a crash DURING a write must never expose a half-written file
#
#  The three crash points used above all sit BETWEEN commits. These two
#  sit inside a write: mid-way through streaming the truncated key file,
#  and after the .meta has been staged but before it is published. The
#  live file must be untouched or complete in both cases - never partial.
# -----------------------------------------------------------------------------

echo "     Testing that a crash mid-write never exposes a partial file..."

dd if=/dev/urandom of=commit_pkey.txt bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=commit_pkey.txt.dec bs=1 count=$(wc -c < commit_pkey.txt) 2>/dev/null
./bin/otp --add-contact partialtest commit_pkey.txt commit_pkey.txt.dec > /dev/null 2>&1

printf 'crash while rewriting the key' > commit_pmsg.txt
OTP_TEST_CRASH_POINT=during_key_truncate ./bin/otp -c partialtest --encrypt \
  < commit_pmsg.txt > /dev/null 2>/dev/null
RC=$?
KEYSIZE=$(wc -c < .keychain/partialtest_enc.key | tr -d ' ')
OFF=$(grep '^EncryptionKeyOffset=' .keychain/partialtest.meta | cut -d= -f2)

if [ $RC -eq 77 ] && [ "$KEYSIZE" = "2000" ] && [ "$OFF" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - crash mid key-rewrite leaves the live key file untouched"
else
  echo "     ! ${RED}FAIL${NC} - key file or metadata changed by an interrupted rewrite (exit $RC, size $KEYSIZE, offset $OFF)"
  exit 1
fi

# Nothing was committed, so the next run must discard and proceed normally
printf 'a fresh message' > commit_pmsg2.txt
./bin/otp -c partialtest --encrypt < commit_pmsg2.txt > commit_pout.bin 2>/dev/null
RC=$?
expected_cipher commit_pkey.txt commit_pmsg2.txt 0 commit_pexp.bin
cmp -s commit_pout.bin commit_pexp.bin
CMP_RC=$?

if [ $RC -eq 0 ] && [ $CMP_RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the next run encrypts from the key's true start, nothing wasted"
else
  echo "     ! ${RED}FAIL${NC} - recovery after an interrupted key rewrite was wrong (exit $RC)"
  exit 1
fi

./bin/otp --remove-contact partialtest > /dev/null 2>&1

# Now the .meta half: staged but not published when the process dies
dd if=/dev/urandom of=commit_mkey.txt bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=commit_mkey.txt.dec bs=1 count=$(wc -c < commit_mkey.txt) 2>/dev/null
./bin/otp --add-contact metapartial commit_mkey.txt commit_mkey.txt.dec > /dev/null 2>&1

printf 'crash after meta staged' > commit_mmsg.txt
OTP_TEST_CRASH_POINT=after_meta_staged ./bin/otp -c metapartial --encrypt \
  < commit_mmsg.txt > /dev/null 2>/dev/null
RC=$?
MSGLEN=$(wc -c < commit_mmsg.txt | tr -d ' ')
EXPECT_KEY=$((2000 - MSGLEN))
KEYSIZE=$(wc -c < .keychain/metapartial_enc.key | tr -d ' ')
SEQ=$(grep '^EncryptedSequence=' .keychain/metapartial.meta | cut -d= -f2)
FIELDS=$(grep -c '=' .keychain/metapartial.meta)

if [ $RC -eq 77 ] && [ "$KEYSIZE" = "$EXPECT_KEY" ] && [ "$SEQ" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - the live .meta is the intact previous version, not a partial write"
else
  echo "     ! ${RED}FAIL${NC} - unexpected state after crash between staging and publishing .meta (exit $RC, key $KEYSIZE, seq $SEQ)"
  exit 1
fi

if [ "$FIELDS" -ge 12 ]; then
  echo "     - ${GREEN}PASS${NC} - the live .meta still parses completely ($FIELDS fields)"
else
  echo "     ! ${RED}FAIL${NC} - the live .meta looks truncated ($FIELDS fields)"
  cat .keychain/metapartial.meta
  exit 1
fi

expected_cipher commit_mkey.txt commit_mmsg.txt 0 commit_mexp.bin
printf 'ignored' | ./bin/otp -c metapartial --encrypt > commit_mout.bin 2>/dev/null
RC=$?
cmp -s commit_mout.bin commit_mexp.bin
CMP_RC=$?

if [ $RC -eq 3 ] && [ $CMP_RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - recovery finishes the interrupted .meta commit and redelivers exactly"
else
  echo "     ! ${RED}FAIL${NC} - recovery after an interrupted .meta commit was wrong (exit $RC)"
  exit 1
fi

./bin/otp --remove-contact metapartial > /dev/null 2>&1
rm -f commit_pkey.txt commit_pmsg.txt commit_pmsg2.txt commit_pout.bin commit_pexp.bin
rm -f commit_mkey.txt commit_mmsg.txt commit_mout.bin commit_mexp.bin

# -----------------------------------------------------------------------------
#  decrypt-side parity
#
#  Decryption runs the same protocol as encryption, parameterised by
#  direction. "Same code path" is exactly the claim that stops being true
#  without anyone noticing, so the rows the encrypt tests above cover are
#  exercised here against the decryption key too.
# -----------------------------------------------------------------------------

echo "     Testing decrypt-side parity (bounds, resync, delivery)..."

dd if=/dev/urandom of=commit_dkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_dkey.txt.dec bs=1 count=$(wc -c < commit_dkey.txt) 2>/dev/null
./bin/otp --add-contact decparity commit_dkey.txt commit_dkey.txt.dec > /dev/null 2>&1

# 1. input longer than the remaining decryption key, spanning chunks
dd if=/dev/urandom of=commit_dbig.bin bs=1 count=1500 2>/dev/null
./bin/otp -c decparity --decrypt < commit_dbig.bin > commit_dout.bin 2>commit_derr1.log
RC=$?
OFF=$(grep '^DecryptionKeyOffset=' .keychain/decparity.meta | cut -d= -f2)
OUTSIZE=$(wc -c < commit_dout.bin | tr -d ' ')

if [ $RC -ne 0 ] && [ "$OFF" = "0" ] && [ "$OUTSIZE" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - oversized ciphertext is refused with no plaintext leaked and no key spent"
else
  echo "     ! ${RED}FAIL${NC} - oversized decrypt misbehaved (exit $RC, offset $OFF, $OUTSIZE bytes out)"
  cat commit_derr1.log
  exit 1
fi

# 2. decryption metadata drifted from the decryption key file
dd if=commit_dkey.txt of=.keychain/decparity_dec.key bs=1 count=700 2>/dev/null
printf 'heal the dec side' > commit_dmsg.txt
./bin/otp -c decparity --decrypt < commit_dmsg.txt > commit_dout2.bin 2>commit_derr2.log
RC=$?
grep -q "decryption key metadata for contact 'decparity'" commit_derr2.log
GREP_RC=$?
SIZE=$(grep '^DecryptionKeySize=' .keychain/decparity.meta | cut -d= -f2)
ACTUAL=$(wc -c < .keychain/decparity_dec.key | tr -d ' ')

if [ $RC -eq 0 ] && [ $GREP_RC -eq 0 ] && [ "$SIZE" = "$ACTUAL" ]; then
  echo "     - ${GREEN}PASS${NC} - drifted decryption metadata self-heals toward the key file"
else
  echo "     ! ${RED}FAIL${NC} - decrypt resync did not heal (exit $RC, meta $SIZE, actual $ACTUAL)"
  cat commit_derr2.log
  exit 1
fi

# 3. a rolled-back decryption key must be refused, never adopted
cat commit_dkey.txt > .keychain/decparity_dec.key
printf 'should be refused' | ./bin/otp -c decparity --decrypt > /dev/null 2>commit_derr3.log
RC=$?
grep -q "restored or rolled back" commit_derr3.log
GREP_RC=$?

if [ $RC -ne 0 ] && [ $GREP_RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - a rolled-back decryption key is refused, not adopted"
else
  echo "     ! ${RED}FAIL${NC} - a rolled-back decryption key was accepted (exit $RC)"
  cat commit_derr3.log
  exit 1
fi

./bin/otp --remove-contact decparity > /dev/null 2>&1

# 4. a failed delivery of PLAINTEXT must be detected and recoverable -
#    this is the case where losing the output is unrecoverable, because
#    the decryption key bytes are already gone.
if [ -w /dev/full ]; then
  dd if=/dev/urandom of=commit_dfkey.txt bs=1 count=1000 2>/dev/null
  dd if=/dev/urandom of=commit_dfkey.txt.dec bs=1 count=$(wc -c < commit_dfkey.txt) 2>/dev/null
  ./bin/otp --add-contact decfull commit_dfkey.txt commit_dfkey.txt.dec > /dev/null 2>&1

  printf 'plaintext that must not be lost' > commit_dfplain.txt
  expected_cipher commit_dfkey.txt.dec commit_dfplain.txt 0 commit_dfcipher.bin

  ./bin/otp -c decfull --decrypt < commit_dfcipher.bin > /dev/full 2>commit_dferr.log
  RC=$?
  PEND=$(ls .keychain/ 2>/dev/null | grep -c "decfull_dec_pending_seq")

  if [ $RC -ne 0 ] && [ "$PEND" = "1" ]; then
    echo "     - ${GREEN}PASS${NC} - failed plaintext delivery reports failure and keeps the verified copy"
  else
    echo "     ! ${RED}FAIL${NC} - failed plaintext delivery lost the message (exit $RC, $PEND pending)"
    exit 1
  fi

  printf 'ignored' | ./bin/otp -c decfull --decrypt > commit_dfout.bin 2>/dev/null
  RC=$?
  cmp -s commit_dfout.bin commit_dfplain.txt
  CMP_RC=$?

  if [ $RC -eq 3 ] && [ $CMP_RC -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - the plaintext is recovered byte-exact on the next run"
  else
    echo "     ! ${RED}FAIL${NC} - plaintext not recovered after failed delivery (exit $RC)"
    exit 1
  fi

  ./bin/otp --remove-contact decfull > /dev/null 2>&1
  rm -f commit_dfkey.txt commit_dfplain.txt commit_dfcipher.bin commit_dfout.bin commit_dferr.log
fi

rm -f commit_dkey.txt commit_dbig.bin commit_dout.bin commit_dout2.bin commit_dmsg.txt
rm -f commit_derr1.log commit_derr2.log commit_derr3.log

# -----------------------------------------------------------------------------
#  the fourth recovery outcome: a state matching no known-safe window
#
#  The truth table has three recognised windows. Anything else - a pending
#  artifact whose recorded key range cannot be reconciled with the key
#  file and the metadata - must be discarded defensively rather than
#  guessed at, and the run must then continue normally. Guessing here
#  would be the one place recovery could itself cause reuse.
# -----------------------------------------------------------------------------

echo "     Testing recovery from a state matching no known window..."

dd if=/dev/urandom of=commit_ukey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_ukey.txt.dec bs=1 count=$(wc -c < commit_ukey.txt) 2>/dev/null
./bin/otp --add-contact unknownstate commit_ukey.txt commit_ukey.txt.dec > /dev/null 2>&1

printf 'establish some state' | ./bin/otp -c unknownstate --encrypt > /dev/null 2>&1
OFF_BEFORE=$(grep '^EncryptionKeyOffset=' .keychain/unknownstate.meta | cut -d= -f2)

# A pending artifact tagged with a range that fits no window at all
printf 'nonsense payload' > ".keychain/unknownstate_enc_pending_seq99_off12345_len77.bin"

printf 'a real new message' > commit_umsg.txt
./bin/otp -c unknownstate --encrypt < commit_umsg.txt > commit_uout.bin 2>commit_uerr.log
RC=$?

grep -q "does not match a recognized recovery state" commit_uerr.log
G1=$?
grep -q "discarded an unrecoverable pending encryption artifact" commit_uerr.log
G2=$?
LEFT=$(ls .keychain/ 2>/dev/null | grep -c "unknownstate_enc_pending")

if [ $G1 -eq 0 ] && [ $G2 -eq 0 ] && [ "$LEFT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - an unrecognised pending artifact is reported and discarded"
else
  echo "     ! ${RED}FAIL${NC} - unrecognised state not handled (warnings $G1/$G2, $LEFT left)"
  cat commit_uerr.log
  exit 1
fi

# Crucially, the run must then process its own input normally
expected_cipher commit_ukey.txt commit_umsg.txt "$OFF_BEFORE" commit_uexp.bin
cmp -s commit_uout.bin commit_uexp.bin
CMP_RC=$?
MSGLEN=$(wc -c < commit_umsg.txt | tr -d ' ')
EXPECT_OFF=$((OFF_BEFORE + MSGLEN))
OFF_AFTER=$(grep '^EncryptionKeyOffset=' .keychain/unknownstate.meta | cut -d= -f2)

if [ $RC -eq 0 ] && [ $CMP_RC -eq 0 ] && [ "$OFF_AFTER" = "$EXPECT_OFF" ]; then
  echo "     - ${GREEN}PASS${NC} - the run continues normally, consuming key exactly once"
else
  echo "     ! ${RED}FAIL${NC} - run did not continue correctly (exit $RC, offset $OFF_AFTER vs $EXPECT_OFF)"
  exit 1
fi

./bin/otp --remove-contact unknownstate > /dev/null 2>&1
rm -f commit_ukey.txt commit_umsg.txt commit_uout.bin commit_uexp.bin commit_uerr.log

# -----------------------------------------------------------------------------
#  more than one pending artifact for the same contact and direction
#
#  Only one can exist under normal operation, since reconcile runs before
#  anything new is staged. If several are somehow present, picking one
#  arbitrarily would be a guess about which key range was really spent, so
#  the extras are discarded rather than reconciled.
# -----------------------------------------------------------------------------

echo "     Testing that duplicate pending artifacts are discarded, not guessed at..."

dd if=/dev/urandom of=commit_xkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_xkey.txt.dec bs=1 count=$(wc -c < commit_xkey.txt) 2>/dev/null
./bin/otp --add-contact extrapending commit_xkey.txt commit_xkey.txt.dec > /dev/null 2>&1

printf 'first payload'  > ".keychain/extrapending_enc_pending_seq1_off0_len13.bin"
printf 'second payload' > ".keychain/extrapending_enc_pending_seq2_off500_len14.bin"

printf 'new work' > commit_xmsg.txt
./bin/otp -c extrapending --encrypt < commit_xmsg.txt > commit_xout.bin 2>commit_xerr.log
RC=$?

grep -q "discarding unexpected extra pending artifact" commit_xerr.log
G1=$?
LEFT=$(ls .keychain/ 2>/dev/null | grep -c "extrapending_enc_pending")

if [ $G1 -eq 0 ] && [ "$LEFT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - extra pending artifacts are reported and removed"
else
  echo "     ! ${RED}FAIL${NC} - duplicate pending artifacts mishandled (warning $G1, $LEFT left)"
  cat commit_xerr.log
  exit 1
fi

expected_cipher commit_xkey.txt commit_xmsg.txt 0 commit_xexp.bin
cmp -s commit_xout.bin commit_xexp.bin
CMP_RC=$?
if [ $RC -eq 0 ] && [ $CMP_RC -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the run proceeds from the key's true start afterwards"
else
  echo "     ! ${RED}FAIL${NC} - run after duplicate artifacts was wrong (exit $RC)"
  exit 1
fi

./bin/otp --remove-contact extrapending > /dev/null 2>&1
rm -f commit_xkey.txt commit_xmsg.txt commit_xout.bin commit_xexp.bin commit_xerr.log

# -----------------------------------------------------------------------------
#  a pending artifact whose key file cannot be read
#
#  Reconciliation compares the artifact's recorded range against the key
#  file's real size. If the key file cannot be read there is no basis for
#  any conclusion - but the failure may be transient, so the artifact is
#  KEPT and the run aborted, letting a later run reconcile it once the
#  key file is readable again. Discarding it here would destroy, on the
#  decrypt side, the only copy of a recovered plaintext.
# -----------------------------------------------------------------------------

echo "     Testing reconciliation when the key file is unreadable..."

dd if=/dev/urandom of=commit_nkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_nkey.txt.dec bs=1 count=$(wc -c < commit_nkey.txt) 2>/dev/null
./bin/otp --add-contact nokeyfile commit_nkey.txt commit_nkey.txt.dec > /dev/null 2>&1

printf 'orphaned payload' > ".keychain/nokeyfile_enc_pending_seq1_off0_len16.bin"
mv .keychain/nokeyfile_enc.key commit_nkey_hidden.bin

printf 'attempt' | ./bin/otp -c nokeyfile --encrypt > /dev/null 2>commit_nerr.log
RC=$?
grep -q "keeping the pending artifact" commit_nerr.log
G1=$?
LEFT=$(ls .keychain/ 2>/dev/null | grep -c "nokeyfile_enc_pending")

if [ $RC -ne 0 ] && [ $G1 -eq 0 ] && [ "$LEFT" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - the artifact is kept and the run aborts"
else
  echo "     ! ${RED}FAIL${NC} - missing key file during reconcile mishandled (exit $RC, warn $G1, $LEFT left)"
  cat commit_nerr.log
  exit 1
fi

OFF=$(grep '^EncryptionKeyOffset=' .keychain/nokeyfile.meta | cut -d= -f2)
if [ "$OFF" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - no key material was recorded as consumed"
else
  echo "     ! ${RED}FAIL${NC} - offset moved to $OFF despite an aborted run"
  exit 1
fi

# Once the key file is back, the kept artifact must reconcile normally:
# this one was never committed (window 1), so it is discarded as stale
# and the run proceeds.
mv commit_nkey_hidden.bin .keychain/nokeyfile_enc.key
printf 'attempt' | ./bin/otp -c nokeyfile --encrypt > /dev/null 2>commit_nerr2.log
RC=$?
LEFT=$(ls .keychain/ 2>/dev/null | grep -c "nokeyfile_enc_pending")
if [ $RC -eq 0 ] && [ "$LEFT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - the kept artifact reconciles once the key file is readable again"
else
  echo "     ! ${RED}FAIL${NC} - kept artifact not reconciled after the failure cleared (exit $RC, $LEFT left)"
  cat commit_nerr2.log
  exit 1
fi

./bin/otp --remove-contact nokeyfile > /dev/null 2>&1
rm -f commit_nkey.txt commit_nkey.txt.dec commit_nerr.log commit_nerr2.log

# -----------------------------------------------------------------------------
#  decrypt side: an unreadable key file must not cost the plaintext
#
#  After a window-2 crash the pending artifact holds the ONLY copy of the
#  recovered plaintext - the key bytes that produced it are already
#  truncated away on both sides. If the key file then cannot be statted
#  while reconciling (a transient mount hiccup, fd exhaustion), the
#  artifact must survive the aborted run so that a later run can
#  redeliver it. Discarding it would lose the message forever, which is
#  exactly what the commit machinery exists to prevent.
# -----------------------------------------------------------------------------

echo "     Testing that an unreadable key file cannot destroy recovered plaintext..."

dd if=/dev/urandom of=commit_ndkey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=commit_ndkey.txt.dec bs=1 count=1000 2>/dev/null
./bin/otp --add-contact nodeckey commit_ndkey.txt commit_ndkey.txt.dec > /dev/null 2>&1

printf 'sole surviving copy of this message' > commit_ndplain.txt
# The peer encrypts with what is our DECRYPTION key.
expected_cipher commit_ndkey.txt.dec commit_ndplain.txt 0 commit_ndcipher.bin

OTP_TEST_CRASH_POINT=after_key_publish ./bin/otp -c nodeckey --decrypt < commit_ndcipher.bin > /dev/null 2>/dev/null
if [ $? -eq 77 ]; then
  echo "     - ${GREEN}PASS${NC} - simulated crash landed after the key bytes were spent"
else
  echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected"
  exit 1
fi

# Make the key file unstattable for the recovery run, keeping a copy so
# the "failure" is transient.
mv .keychain/nodeckey_dec.key commit_ndkey_hidden.bin

printf 'ignored' | ./bin/otp -c nodeckey --decrypt > /dev/null 2>commit_nderr.log
RC=$?
grep -q "keeping the pending artifact" commit_nderr.log
G1=$?
PENDING=$(ls .keychain/nodeckey_dec_pending_seq* 2>/dev/null | head -n 1)

if [ $RC -ne 0 ] && [ $G1 -eq 0 ] && [ -n "$PENDING" ]; then
  echo "     - ${GREEN}PASS${NC} - the run aborts and the plaintext artifact survives"
else
  echo "     ! ${RED}FAIL${NC} - recovery with an unreadable key file mishandled (exit $RC, warn $G1, pending '$PENDING')"
  cat commit_nderr.log
  exit 1
fi

cmp -s "$PENDING" commit_ndplain.txt
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the kept artifact is byte-for-byte the missing plaintext"
else
  echo "     ! ${RED}FAIL${NC} - the kept artifact does not hold the plaintext"
  exit 1
fi

# The failure clears; the next run must finish the interrupted commit and
# redeliver the plaintext intact.
mv commit_ndkey_hidden.bin .keychain/nodeckey_dec.key

printf 'ignored' | ./bin/otp -c nodeckey --decrypt > commit_ndout.bin 2>commit_nderr2.log
grep -q "Recovered incomplete delivery" commit_nderr2.log
G2=$?
cmp -s commit_ndout.bin commit_ndplain.txt
C2=$?
LEFT=$(ls .keychain/ 2>/dev/null | grep -c "nodeckey_dec_pending")

if [ $G2 -eq 0 ] && [ $C2 -eq 0 ] && [ "$LEFT" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - once the key file is back the message is redelivered intact"
else
  echo "     ! ${RED}FAIL${NC} - redelivery after the failure cleared went wrong (recover $G2, cmp $C2, $LEFT left)"
  cat commit_nderr2.log
  exit 1
fi

./bin/otp --remove-contact nodeckey > /dev/null 2>&1
rm -f commit_ndkey.txt commit_ndkey.txt.dec commit_ndplain.txt commit_ndcipher.bin commit_ndout.bin
rm -f commit_nderr.log commit_nderr2.log

# -----------------------------------------------------------------------------
#  I/O failures while committing
#
#  Every write in the commit path is checked, but checks that never run
#  are indistinguishable from checks that do not work. These drive real
#  filesystem failures - an unwritable keychain directory, and a blocked
#  staging path - through the three places a commit can fail to even
#  begin. Skipped when running as root, which bypasses permission checks.
# -----------------------------------------------------------------------------

if [ "$(id -u)" != "0" ]; then
  echo "     Testing that I/O failures during commit are caught..."

  dd if=/dev/urandom of=commit_iokey.txt bs=1 count=1000 2>/dev/null
  dd if=/dev/urandom of=commit_iokey.txt.dec bs=1 count=$(wc -c < commit_iokey.txt) 2>/dev/null
  ./bin/otp --add-contact iofail commit_iokey.txt commit_iokey.txt.dec > /dev/null 2>&1

  # 1. the contact lock cannot be created at all
  #    Adding the contact now takes (and so creates) iofail.lock itself, so
  #    remove it first: this sub-case needs the lock file absent so that the
  #    encrypt below must create it in the (about to be) unwritable dir.
  rm -f .keychain/iofail.lock
  chmod 500 .keychain
  printf 'blocked' | ./bin/otp -c iofail --encrypt > /dev/null 2>commit_ioerr1.log
  RC=$?
  chmod 700 .keychain
  grep -q "cannot create lock file" commit_ioerr1.log
  G=$?
  if [ $RC -ne 0 ] && [ $G -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - a lock that cannot be created aborts the operation"
  else
    echo "     ! ${RED}FAIL${NC} - unusable lock file not reported (exit $RC)"
    cat commit_ioerr1.log
    exit 1
  fi

  # 2. the lock exists, but the staging file cannot be created
  printf 'make the lock' | ./bin/otp -c iofail --encrypt > /dev/null 2>&1
  OFF_BEFORE=$(grep '^EncryptionKeyOffset=' .keychain/iofail.meta | cut -d= -f2)
  chmod 500 .keychain
  printf 'blocked too' | ./bin/otp -c iofail --encrypt > /dev/null 2>commit_ioerr2.log
  RC=$?
  chmod 700 .keychain
  OFF_AFTER=$(grep '^EncryptionKeyOffset=' .keychain/iofail.meta | cut -d= -f2)
  grep -q "cannot create staging file" commit_ioerr2.log
  G=$?
  if [ $RC -ne 0 ] && [ $G -eq 0 ] && [ "$OFF_AFTER" = "$OFF_BEFORE" ]; then
    echo "     - ${GREEN}PASS${NC} - a staging file that cannot be created aborts before any key is spent"
  else
    echo "     ! ${RED}FAIL${NC} - unusable staging file mishandled (exit $RC, offset $OFF_BEFORE->$OFF_AFTER)"
    cat commit_ioerr2.log
    exit 1
  fi

  # 3. the metadata staging path is blocked, so the .meta write fails
  #    *after* the key file has already been committed - the window-2
  #    state, reached through an I/O error rather than a crash.
  KEY_BEFORE=$(wc -c < .keychain/iofail_enc.key | tr -d ' ')
  mkdir -p .keychain/iofail.meta.tmp
  touch .keychain/iofail.meta.tmp/blocker
  printf 'meta write fails' > commit_iomsg.txt
  ./bin/otp -c iofail --encrypt < commit_iomsg.txt > /dev/null 2>commit_ioerr3.log
  RC=$?
  rm -rf .keychain/iofail.meta.tmp
  MSGLEN=$(wc -c < commit_iomsg.txt | tr -d ' ')
  KEY_AFTER=$(wc -c < .keychain/iofail_enc.key | tr -d ' ')
  EXPECT=$((KEY_BEFORE - MSGLEN))
  grep -q "cannot create .keychain/iofail.meta.tmp" commit_ioerr3.log
  G=$?

  if [ $RC -ne 0 ] && [ $G -eq 0 ] && [ "$KEY_AFTER" = "$EXPECT" ]; then
    echo "     - ${GREEN}PASS${NC} - a failed .meta write is caught, leaving a recoverable state"
  else
    echo "     ! ${RED}FAIL${NC} - failed .meta write mishandled (exit $RC, key $KEY_BEFORE->$KEY_AFTER)"
    cat commit_ioerr3.log
    exit 1
  fi

  # and that state must recover exactly like a crash in the same window
  expected_cipher commit_iokey.txt commit_iomsg.txt "$OFF_BEFORE" commit_ioexp.bin
  printf 'ignored' | ./bin/otp -c iofail --encrypt > commit_ioout.bin 2>/dev/null
  RC=$?
  cmp -s commit_ioout.bin commit_ioexp.bin
  CMP_RC=$?
  if [ $RC -eq 3 ] && [ $CMP_RC -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - the interrupted commit recovers and redelivers byte-exact"
  else
    echo "     ! ${RED}FAIL${NC} - recovery after a failed .meta write was wrong (exit $RC)"
    exit 1
  fi

  ./bin/otp --remove-contact iofail > /dev/null 2>&1
  rm -f commit_iokey.txt commit_iomsg.txt commit_ioout.bin commit_ioexp.bin
  rm -f commit_ioerr1.log commit_ioerr2.log commit_ioerr3.log
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf .keychain

echo ""
exit 0
