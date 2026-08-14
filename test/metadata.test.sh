#!/bin/sh

# Per-contact metadata file tests.
#
# keychain.txt used to be a single file holding every contact's metadata,
# rewritten in full on every save. Two processes operating on two
# DIFFERENT contacts at the same time could race on that shared file -
# whichever finished last would silently overwrite the other's update.
# Each contact's metadata now lives in its own file
# (.keychain/<contact>.meta), so two different contacts can no longer
# collide on a save at all - this is verified directly below with real
# concurrent processes, not simulated.
#
# This also covers the one-time migration from the legacy combined
# keychain.txt format (src/keychain.c: migrate_legacy_keychain_if_needed),
# including resuming an interrupted migration.

rm -f keychain.txt keychain.txt.migrated
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
./bin/otp --add-contact metaA meta_keyA.txt meta_keyA.txt > /dev/null 2>&1
./bin/otp --add-contact metaB meta_keyB.txt meta_keyB.txt > /dev/null 2>&1

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
  echo "     - PASS - both concurrent operations on different contacts succeeded"
else
  echo "     ! FAIL - a concurrent operation on a different contact failed (A=$RCA B=$RCB)"
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
  echo "     - PASS - both contacts' metadata reflects their own update - neither was overwritten by the other"
else
  echo "     ! FAIL - one contact's metadata update was lost, overwritten by the other's concurrent save"
  echo "$OUTPUT_A"
  echo "$OUTPUT_B"
  exit 1
fi

# Also confirm the ciphertext each process produced is actually correct,
# not just that the bookkeeping looks right.
dd if=meta_keyA.txt of=meta_sliceA.tmp bs=1 count="$LENA" 2>/dev/null
./bin/otp meta_sliceA.tmp < meta_plainA.txt > meta_expectedA.bin 2>/dev/null
rm -f meta_sliceA.tmp meta_sliceA.tmp.*.next

dd if=meta_keyB.txt of=meta_sliceB.tmp bs=1 count="$LENB" 2>/dev/null
./bin/otp meta_sliceB.tmp < meta_plainB.txt > meta_expectedB.bin 2>/dev/null
rm -f meta_sliceB.tmp meta_sliceB.tmp.*.next

cmp -s meta_cipherA.bin meta_expectedA.bin
CIPHER_A_OK=$?
cmp -s meta_cipherB.bin meta_expectedB.bin
CIPHER_B_OK=$?

if [ $CIPHER_A_OK -eq 0 ] && [ $CIPHER_B_OK -eq 0 ]; then
  echo "     - PASS - both ciphertexts are correct"
else
  echo "     ! FAIL - a ciphertext does not match its expected value"
  exit 1
fi

rm -f meta_keyA.txt meta_keyB.txt meta_plainA.txt meta_plainB.txt
rm -f meta_cipherA.bin meta_cipherB.bin meta_expectedA.bin meta_expectedB.bin
rm -f meta_stderrA.log meta_stderrB.log
rm -f keychain.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  legacy migration: an old combined keychain.txt is converted to
#  per-contact .meta files, transparently, on first load
# -----------------------------------------------------------------------------

echo "     Testing migration from legacy combined keychain.txt..."

dd if=/dev/urandom of=meta_legacykey1.txt bs=1 count=200 2>/dev/null
dd if=/dev/urandom of=meta_legacykey2.txt bs=1 count=300 2>/dev/null

mkdir -p .keychain
chmod 700 .keychain
cp meta_legacykey1.txt .keychain/legacy1_enc.key
cp meta_legacykey1.txt .keychain/legacy1_dec.key
cp meta_legacykey2.txt .keychain/legacy2_enc.key
cp meta_legacykey2.txt .keychain/legacy2_dec.key

cat > keychain.txt << 'EOF'
# OTP Keychain File
# Format: key=value pairs per contact

[CONTACT]
Name=legacy1
EncryptionKeyPath=.keychain/legacy1_enc.key
EncryptionKeySize=200
EncryptionKeyOffset=0
EncryptedSequence=0
DecryptionKeyPath=.keychain/legacy1_dec.key
DecryptionKeySize=200
DecryptionKeyOffset=0
DecryptedSequence=0
LastMessageSent=
LastMessageSentSize=0
RetryCount=0
LastMessageSentAt=0
LastMessageReceivedAt=0

[CONTACT]
Name=legacy2
EncryptionKeyPath=.keychain/legacy2_enc.key
EncryptionKeySize=300
EncryptionKeyOffset=0
EncryptedSequence=0
DecryptionKeyPath=.keychain/legacy2_dec.key
DecryptionKeySize=300
DecryptionKeyOffset=0
DecryptedSequence=0
LastMessageSent=
LastMessageSentSize=0
RetryCount=0
LastMessageSentAt=0
LastMessageReceivedAt=0

EOF

OUTPUT=$(./bin/otp --list-contacts 2>meta_migrate_stderr.log)

echo "$OUTPUT" | grep -q "legacy1"
L1_OK=$?
echo "$OUTPUT" | grep -q "legacy2"
L2_OK=$?
if [ $L1_OK -eq 0 ] && [ $L2_OK -eq 0 ]; then
  echo "     - PASS - migrated contacts are visible immediately after migration"
else
  echo "     ! FAIL - migrated contacts not found"
  echo "$OUTPUT"
  exit 1
fi

if [ -f ".keychain/legacy1.meta" ] && [ -f ".keychain/legacy2.meta" ]; then
  echo "     - PASS - a .meta file was created for each legacy contact"
else
  echo "     ! FAIL - .meta files were not created during migration"
  ls .keychain/
  exit 1
fi

if [ -f "keychain.txt.migrated" ] && [ ! -f "keychain.txt" ]; then
  echo "     - PASS - legacy keychain.txt was preserved as keychain.txt.migrated and retired"
else
  echo "     ! FAIL - legacy keychain.txt was not properly retired after migration"
  exit 1
fi

grep -q "Note: migrated 2 contact" meta_migrate_stderr.log
if [ $? -eq 0 ]; then
  echo "     - PASS - migration was reported to the user"
else
  echo "     ! FAIL - migration was not reported"
  cat meta_migrate_stderr.log
  exit 1
fi

printf 'after migration' | ./bin/otp -c legacy1 --encrypt > meta_migrate_cipher.bin 2>meta_migrate_stderr2.log
RC=$?
if [ $RC -eq 0 ]; then
  echo "     - PASS - migrated contact works normally for new operations"
else
  echo "     ! FAIL - migrated contact failed to encrypt"
  cat meta_migrate_stderr2.log
  exit 1
fi

grep -q "migrated" meta_migrate_stderr2.log
if [ $? -ne 0 ]; then
  echo "     - PASS - migration did not re-run on a subsequent load"
else
  echo "     ! FAIL - migration re-ran unnecessarily on a later load"
  exit 1
fi

rm -f meta_legacykey1.txt meta_legacykey2.txt meta_migrate_cipher.bin
rm -f meta_migrate_stderr.log meta_migrate_stderr2.log
rm -f keychain.txt keychain.txt.migrated
rm -rf .keychain

# -----------------------------------------------------------------------------
#  migration must be resumable: if a crash interrupts it after writing
#  some .meta files but before the legacy file is retired, the next load
#  must finish the job rather than leaving contacts stranded
# -----------------------------------------------------------------------------

echo "     Testing migration resumes correctly after an interrupted attempt..."

dd if=/dev/urandom of=meta_legacykey3.txt bs=1 count=150 2>/dev/null
dd if=/dev/urandom of=meta_legacykey4.txt bs=1 count=150 2>/dev/null

mkdir -p .keychain
chmod 700 .keychain
cp meta_legacykey3.txt .keychain/partial1_enc.key
cp meta_legacykey3.txt .keychain/partial1_dec.key
cp meta_legacykey4.txt .keychain/partial2_enc.key
cp meta_legacykey4.txt .keychain/partial2_dec.key

cat > keychain.txt << 'EOF'
# OTP Keychain File

[CONTACT]
Name=partial1
EncryptionKeyPath=.keychain/partial1_enc.key
EncryptionKeySize=150
EncryptionKeyOffset=0
EncryptedSequence=0
DecryptionKeyPath=.keychain/partial1_dec.key
DecryptionKeySize=150
DecryptionKeyOffset=0
DecryptedSequence=0
LastMessageSent=
LastMessageSentSize=0
RetryCount=0
LastMessageSentAt=0
LastMessageReceivedAt=0

[CONTACT]
Name=partial2
EncryptionKeyPath=.keychain/partial2_enc.key
EncryptionKeySize=150
EncryptionKeyOffset=0
EncryptedSequence=0
DecryptionKeyPath=.keychain/partial2_dec.key
DecryptionKeySize=150
DecryptionKeyOffset=0
DecryptedSequence=0
LastMessageSent=
LastMessageSentSize=0
RetryCount=0
LastMessageSentAt=0
LastMessageReceivedAt=0

EOF

# Simulate a migration that was interrupted after writing partial1.meta
# but before partial2.meta or the final retirement of keychain.txt.
cat > .keychain/partial1.meta << 'EOF'
[CONTACT]
Name=partial1
EncryptionKeyPath=.keychain/partial1_enc.key
EncryptionKeySize=150
EncryptionKeyOffset=0
EncryptedSequence=0
DecryptionKeyPath=.keychain/partial1_dec.key
DecryptionKeySize=150
DecryptionKeyOffset=0
DecryptedSequence=0
LastMessageSent=
LastMessageSentSize=0
RetryCount=0
LastMessageSentAt=0
LastMessageReceivedAt=0

EOF

./bin/otp --list-contacts > /dev/null 2>&1

if [ -f ".keychain/partial1.meta" ] && [ -f ".keychain/partial2.meta" ] && [ ! -f "keychain.txt" ]; then
  echo "     - PASS - interrupted migration resumed and completed on the next load"
else
  echo "     ! FAIL - interrupted migration did not complete correctly"
  ls .keychain/ 2>&1
  ls keychain.txt* 2>&1
  exit 1
fi

rm -f meta_legacykey3.txt meta_legacykey4.txt
rm -f keychain.txt keychain.txt.migrated

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -f keychain.txt keychain.txt.migrated
rm -rf .keychain

echo ""
exit 0
