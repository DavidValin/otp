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

# Per-contact metadata file tests.
#
# Each contact's metadata lives in its own file (.keychain/<contact>.meta),
# so two contacts share no mutable state and concurrent operations on two
# DIFFERENT contacts cannot collide on a save at all. That is verified
# below with real concurrent processes, not simulated. The second section
# checks that a .meta file stays a fixed size no matter how much traffic
# passes through the contact.

rm -rf .keychain

echo ""
echo "   - Per-contact metadata files"

# -----------------------------------------------------------------------------
#  concurrent operations on DIFFERENT contacts must not race on shared
#  storage - this is the actual bug being fixed here
# -----------------------------------------------------------------------------

echo "     Testing concurrent operations on different contacts do not race..."

dd if=/dev/urandom of=meta_keyA.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=meta_keyB.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=meta_keyA.txt.dec bs=1 count=$(wc -c < meta_keyA.txt | tr -d ' ') 2>/dev/null
./bin/otp --add-contact metaA meta_keyA.txt meta_keyA.txt.dec > /dev/null 2>&1
dd if=/dev/urandom of=meta_keyB.txt.dec bs=1 count=$(wc -c < meta_keyB.txt | tr -d ' ') 2>/dev/null
./bin/otp --add-contact metaB meta_keyB.txt meta_keyB.txt.dec > /dev/null 2>&1

printf 'message for contact A, padded to be a decent length AAAAAAAAAAAA' > meta_plainA.txt
printf 'message for contact B, padded to be a decent length BBBBBBBBBBBB' > meta_plainB.txt

./bin/otp -c metaA --encrypt < meta_plainA.txt > meta_cipherA.bin 2>meta_stderrA.log &
PIDA=$!
./bin/otp -c metaB --encrypt < meta_plainB.txt > meta_cipherB.bin 2>meta_stderrB.log &
PIDB=$!
wait $PIDA
RCA=$?
wait $PIDB
RCB=$?

if [ $RCA -eq 0 ] && [ $RCB -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - both concurrent operations on different contacts succeeded"
else
  echo "     ! ${RED}FAIL${NC} - a concurrent operation on a different contact failed (A=$RCA B=$RCB)"
  cat meta_stderrA.log meta_stderrB.log
  exit 1
fi

LENA=$(wc -c < meta_plainA.txt | tr -d ' ')
LENB=$(wc -c < meta_plainB.txt | tr -d ' ')

OUTPUT_A=$(./bin/otp --show-contact metaA)
OUTPUT_B=$(./bin/otp --show-contact metaB)

SEQ_A_OK=$(echo "$OUTPUT_A" | grep -c "EncryptedSequence: 1")
OFF_A_OK=$(echo "$OUTPUT_A" | grep -c "EncryptionKeyOffset: $LENA")
SEQ_B_OK=$(echo "$OUTPUT_B" | grep -c "EncryptedSequence: 1")
OFF_B_OK=$(echo "$OUTPUT_B" | grep -c "EncryptionKeyOffset: $LENB")

if [ "$SEQ_A_OK" = "1" ] && [ "$OFF_A_OK" = "1" ] && [ "$SEQ_B_OK" = "1" ] && [ "$OFF_B_OK" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - both contacts' metadata reflects their own update - neither was overwritten by the other"
else
  echo "     ! ${RED}FAIL${NC} - one contact's metadata update was lost, overwritten by the other's concurrent save"
  echo "$OUTPUT_A"
  echo "$OUTPUT_B"
  exit 1
fi

# Also confirm the ciphertext each process produced is actually correct,
# not just that the bookkeeping looks right.
. test/xor.helper.sh
xor_with_key meta_keyA.txt meta_plainA.txt meta_expectedA.bin
xor_with_key meta_keyB.txt meta_plainB.txt meta_expectedB.bin

cmp -s meta_cipherA.bin meta_expectedA.bin
CIPHER_A_OK=$?
cmp -s meta_cipherB.bin meta_expectedB.bin
CIPHER_B_OK=$?

if [ $CIPHER_A_OK -eq 0 ] && [ $CIPHER_B_OK -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - both ciphertexts are correct"
else
  echo "     ! ${RED}FAIL${NC} - a ciphertext does not match its expected value"
  exit 1
fi

rm -f meta_keyA.txt meta_keyB.txt meta_plainA.txt meta_plainB.txt
rm -f meta_cipherA.bin meta_cipherB.bin meta_expectedA.bin meta_expectedB.bin
rm -f meta_stderrA.log meta_stderrB.log
rm -rf .keychain

# -----------------------------------------------------------------------------
#  metadata must not grow with message size
#
#  A copy of the last ciphertext used to be base64-encoded into the .meta
#  file. That made the file 1.33x the message size, and because the parser
#  reads lines into a fixed buffer, any message over ~12.5MB came back
#  truncated while the declared LastMessageSentSize still claimed the full
#  length - so the next save re-encoded that declared length out of a
#  shorter buffer, reading several MB of unrelated heap (which at that
#  moment holds key material and plaintext) into the .meta file on disk.
#  The field is gone; metadata is now fixed-size regardless of traffic.
# -----------------------------------------------------------------------------

echo "     Testing that metadata size is independent of message size..."

dd if=/dev/urandom of=meta_bigkey.txt bs=1048576 count=40 2>/dev/null
dd if=/dev/urandom of=meta_bigkey.txt.dec bs=1 count=$(wc -c < meta_bigkey.txt | tr -d ' ') 2>/dev/null
./bin/otp --add-contact bulky meta_bigkey.txt meta_bigkey.txt.dec > /dev/null 2>&1

META_EMPTY=$(wc -c < .keychain/bulky.meta | tr -d ' ')

# Comfortably past the ~12.5MB point where the old truncation kicked in
dd if=/dev/urandom of=meta_bigmsg.bin bs=1048576 count=14 2>/dev/null
./bin/otp -c bulky --encrypt < meta_bigmsg.bin > meta_bigcipher.bin 2>/dev/null
RC=$?

META_AFTER=$(wc -c < .keychain/bulky.meta | tr -d ' ')

if [ $RC -eq 0 ] && [ "$META_AFTER" -lt 4096 ]; then
  echo "     - ${GREEN}PASS${NC} - .meta stayed small after a 14MB message ($META_EMPTY -> $META_AFTER bytes)"
else
  echo "     ! ${RED}FAIL${NC} - .meta grew to $META_AFTER bytes after a 14MB message (exit $RC)"
  exit 1
fi

# The dangerous step was a *later* process loading that .meta and saving
# it again - that is where the out-of-bounds read happened.
./bin/otp --show-contact bulky > /dev/null 2>&1
printf 'trigger a save' | ./bin/otp -c bulky --decrypt > /dev/null 2>&1
RC=$?
OFFSET=$(grep '^EncryptionKeyOffset=' .keychain/bulky.meta | cut -d= -f2)

if [ $RC -eq 0 ] && [ "$OFFSET" = "14680064" ]; then
  echo "     - ${GREEN}PASS${NC} - a later process reloads and re-saves that .meta safely"
else
  echo "     ! ${RED}FAIL${NC} - reload/re-save after a large message misbehaved (exit $RC, offset $OFFSET)"
  exit 1
fi

# And the message itself must still round-trip
./bin/otp --remove-contact bulky > /dev/null 2>&1

rm -f meta_bigkey.txt meta_bigmsg.bin meta_bigcipher.bin

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf .keychain
rm -f meta_*

echo ""
exit 0
