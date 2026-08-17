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

# Keychain tests for OTP

# Clean up any existing test keychain
rm -rf .keychain

echo ""
echo "   - Keychain functionality"

# -----------------------------------------------------------------------------
#  test add contact
# -----------------------------------------------------------------------------

echo "     Testing add contact..."

./bin/otp --add-contact alice > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - add contact succeeded"
else
  echo "     ! ${RED}FAIL${NC} - add contact failed"
  exit -1
fi

if test -f ".keychain/alice.meta"; then
  echo "     - ${GREEN}PASS${NC} - per-contact metadata file .keychain/alice.meta was created"
else
  echo "     ! ${RED}FAIL${NC} - .keychain/alice.meta was NOT created"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test has contact
# -----------------------------------------------------------------------------

echo "     Testing has contact..."

./bin/otp --has-contact alice > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - has contact found alice"
else
  echo "     ! ${RED}FAIL${NC} - has contact did not find alice"
  exit -1
fi

./bin/otp --has-contact bob > /dev/null
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - has contact correctly reports bob doesn't exist"
else
  echo "     ! ${RED}FAIL${NC} - has contact incorrectly found bob"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test list contacts
# -----------------------------------------------------------------------------

echo "     Testing list contacts..."

OUTPUT=$(./bin/otp --list-contacts)
echo "$OUTPUT" | grep -q "alice"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - list contacts shows alice"
else
  echo "     ! ${RED}FAIL${NC} - list contacts does not show alice"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test add multiple contacts
# -----------------------------------------------------------------------------

echo "     Testing multiple contacts..."

./bin/otp --add-contact bob > /dev/null
./bin/otp --add-contact charlie > /dev/null

OUTPUT=$(./bin/otp --list-contacts)
echo "$OUTPUT" | grep -q "alice"
ALICE_FOUND=$?
echo "$OUTPUT" | grep -q "bob"
BOB_FOUND=$?
echo "$OUTPUT" | grep -q "charlie"
CHARLIE_FOUND=$?

if [ $ALICE_FOUND -eq 0 ] && [ $BOB_FOUND -eq 0 ] && [ $CHARLIE_FOUND -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - list contacts shows all three contacts"
else
  echo "     ! ${RED}FAIL${NC} - list contacts missing some contacts"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test show contact
# -----------------------------------------------------------------------------

echo "     Testing show contact..."

OUTPUT=$(./bin/otp --show-contact alice)
echo "$OUTPUT" | grep -q "Contact: alice"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - show contact displays alice"
else
  echo "     ! ${RED}FAIL${NC} - show contact does not display alice correctly"
  exit -1
fi

# Check that keys are masked
echo "$OUTPUT" | grep -q "\*\*\*\*\*\*\*"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - show contact masks keys"
else
  echo "     ! ${RED}FAIL${NC} - show contact does not mask keys"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test remove contact
# -----------------------------------------------------------------------------

echo "     Testing remove contact..."

./bin/otp --remove-contact bob > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - remove contact succeeded"
else
  echo "     ! ${RED}FAIL${NC} - remove contact failed"
  exit -1
fi

./bin/otp --has-contact bob > /dev/null
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - bob was successfully removed"
else
  echo "     ! ${RED}FAIL${NC} - bob still exists after removal"
  exit -1
fi

# Verify alice and charlie still exist
./bin/otp --has-contact alice > /dev/null
ALICE_EXISTS=$?
./bin/otp --has-contact charlie > /dev/null
CHARLIE_EXISTS=$?

if [ $ALICE_EXISTS -eq 0 ] && [ $CHARLIE_EXISTS -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - other contacts remain after removal"
else
  echo "     ! ${RED}FAIL${NC} - other contacts were incorrectly affected"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test duplicate contact
# -----------------------------------------------------------------------------

echo "     Testing duplicate contact prevention..."

./bin/otp --add-contact alice > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - duplicate contact correctly rejected"
else
  echo "     ! ${RED}FAIL${NC} - duplicate contact was allowed"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test short options
# -----------------------------------------------------------------------------

echo "     Testing short options..."

./bin/otp -ac dave > /dev/null
./bin/otp -hc dave > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - short option -ac and -hc work"
else
  echo "     ! ${RED}FAIL${NC} - short options don't work"
  exit -1
fi

OUTPUT=$(./bin/otp -lc)
echo "$OUTPUT" | grep -q "dave"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - short option -lc works"
else
  echo "     ! ${RED}FAIL${NC} - short option -lc doesn't work"
  exit -1
fi

OUTPUT=$(./bin/otp -sc dave)
echo "$OUTPUT" | grep -q "Contact: dave"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - short option -sc works"
else
  echo "     ! ${RED}FAIL${NC} - short option -sc doesn't work"
  exit -1
fi

./bin/otp -rc dave > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - short option -rc works"
else
  echo "     ! ${RED}FAIL${NC} - short option -rc doesn't work"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test persistence
# -----------------------------------------------------------------------------

echo "     Testing persistence..."

# The keychain should already be saved with alice and charlie, each in
# its own per-contact metadata file
grep -q "Name=alice" .keychain/alice.meta
ALICE_IN_FILE=$?
grep -q "Name=charlie" .keychain/charlie.meta
CHARLIE_IN_FILE=$?

if [ $ALICE_IN_FILE -eq 0 ] && [ $CHARLIE_IN_FILE -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - contacts persisted to their own metadata files"
else
  echo "     ! ${RED}FAIL${NC} - contacts not properly persisted"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test add contact with key files
# -----------------------------------------------------------------------------

echo "     Testing add contact with key files..."

# Generate a key pair for testing
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | ./bin/otp --new-key-pair 1 testalice testbob > /dev/null 2>&1
rm tmpkey

# Verify key files were created
if [ ! -f "encryption_testalice.txt" ] || [ ! -f "decryption_testalice.txt" ]; then
  echo "     ! ${RED}FAIL${NC} - key pair generation failed"
  exit -1
fi

# Add contact with keys
./bin/otp --add-contact testcontact encryption_testalice.txt decryption_testalice.txt > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - add contact with keys succeeded"
else
  echo "     ! ${RED}FAIL${NC} - add contact with keys failed"
  exit -1
fi

# Verify contact was added
./bin/otp --has-contact testcontact > /dev/null
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - contact with keys exists"
else
  echo "     ! ${RED}FAIL${NC} - contact with keys was not added"
  exit -1
fi

# Verify keys were loaded
OUTPUT=$(./bin/otp --show-contact testcontact)
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* ([1-9][0-9]* bytes)"
ENC_KEY_LOADED=$?
echo "$OUTPUT" | grep -q "DecryptionKey: \*\*\*\*\*\*\* ([1-9][0-9]* bytes)"
DEC_KEY_LOADED=$?

if [ $ENC_KEY_LOADED -eq 0 ] && [ $DEC_KEY_LOADED -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - keys were loaded correctly"
else
  echo "     ! ${RED}FAIL${NC} - keys were not loaded properly"
  exit -1
fi

# Test that key size is correct (1MB = 1048576 bytes)
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* (1048576 bytes)"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - encryption key size is correct"
else
  echo "     ! ${RED}FAIL${NC} - encryption key size is incorrect"
  exit -1
fi

echo "$OUTPUT" | grep -q "DecryptionKey: \*\*\*\*\*\*\* (1048576 bytes)"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - decryption key size is correct"
else
  echo "     ! ${RED}FAIL${NC} - decryption key size is incorrect"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test encryption with contact
# -----------------------------------------------------------------------------

echo "     Testing encryption with contact..."

# Create a contact with keys for testing (fresh keychain from here on)
rm -rf .keychain
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | ./bin/otp --new-key-pair 1 enctest dectest > /dev/null 2>&1
rm tmpkey

./bin/otp --add-contact enctest encryption_enctest.txt decryption_enctest.txt > /dev/null 2>&1

# Encrypt a message
PLAIN_MSG="Hello, World!"
echo -n "$PLAIN_MSG" > test_plain.txt
./bin/otp -c enctest --encrypt < test_plain.txt > test_cipher.bin 2>/dev/null

if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - encryption with contact succeeded"
else
  echo "     ! ${RED}FAIL${NC} - encryption with contact failed"
  exit -1
fi

# Verify cipher text is not the same as plain text (compare file sizes or content)
if ! diff -q test_plain.txt test_cipher.bin > /dev/null 2>&1; then
  echo "     - ${GREEN}PASS${NC} - cipher text differs from plain text"
else
  echo "     ! ${RED}FAIL${NC} - cipher text same as plain text"
  exit -1
fi

# Verify key offset was updated
OUTPUT=$(./bin/otp --show-contact enctest)
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: 13"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - encryption key offset updated correctly"
else
  echo "     ! ${RED}FAIL${NC} - encryption key offset not updated correctly"
  exit -1
fi

# Verify sequence was incremented
echo "$OUTPUT" | grep -q "EncryptedSequence: 1"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - sequence incremented correctly"
else
  echo "     ! ${RED}FAIL${NC} - sequence not incremented"
  exit -1
fi

# Verify LastMessageSentAt was set
echo "$OUTPUT" | grep -q -v "LastMessageSentAt: never"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - LastMessageSentAt timestamp set"
else
  echo "     ! ${RED}FAIL${NC} - LastMessageSentAt not set"
  exit -1
fi

# Verify remaining key size
EXPECTED_REMAINING=$((1048576 - 13))
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* ($EXPECTED_REMAINING bytes)"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - remaining encryption key size correct"
else
  echo "     ! ${RED}FAIL${NC} - remaining encryption key size incorrect"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test decryption with contact
# -----------------------------------------------------------------------------

echo "     Testing decryption with contact..."

# Create Bob with matching keys (Alice's decryption = Bob's encryption)
./bin/otp --add-contact dectest encryption_dectest.txt decryption_dectest.txt > /dev/null 2>&1

# Decrypt the cipher using dectest's decryption key
./bin/otp -c dectest --decrypt < test_cipher.bin > test_decrypted.txt 2>/dev/null

if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - decryption with contact succeeded"
else
  echo "     ! ${RED}FAIL${NC} - decryption with contact failed"
  exit -1
fi

# Verify decrypted text matches original
if diff -q test_plain.txt test_decrypted.txt > /dev/null 2>&1; then
  echo "     - ${GREEN}PASS${NC} - decrypted text matches original plain text"
else
  echo "     ! ${RED}FAIL${NC} - decrypted text does not match"
  cat test_plain.txt
  echo "---"
  cat test_decrypted.txt
  exit -1
fi

# Verify decryption key offset was updated
OUTPUT=$(./bin/otp --show-contact dectest)
echo "$OUTPUT" | grep -q "DecryptionKeyOffset: 13"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - decryption key offset updated correctly"
else
  echo "     ! ${RED}FAIL${NC} - decryption key offset not updated correctly"
  exit -1
fi

# Verify LastMessageReceivedAt was set
echo "$OUTPUT" | grep -q -v "LastMessageReceivedAt: never"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - LastMessageReceivedAt timestamp set"
else
  echo "     ! ${RED}FAIL${NC} - LastMessageReceivedAt not set"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: contact not found
# -----------------------------------------------------------------------------

echo "     Testing error cases..."

echo -n "test" | ./bin/otp -c nonexistent --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - error on nonexistent contact"
else
  echo "     ! ${RED}FAIL${NC} - should error on nonexistent contact"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: contact with empty key
# -----------------------------------------------------------------------------

./bin/otp --add-contact emptykey > /dev/null 2>&1
echo -n "test" | ./bin/otp -c emptykey --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - error on empty encryption key"
else
  echo "     ! ${RED}FAIL${NC} - should error on empty encryption key"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: message too large for key
# -----------------------------------------------------------------------------

# Create contact with very small key
dd if=/dev/urandom of=smallkey.txt bs=1 count=5 2>/dev/null
dd if=/dev/urandom of=smallkey.txt.dec bs=1 count=$(wc -c < smallkey.txt) 2>/dev/null
./bin/otp --add-contact smallkeytest smallkey.txt smallkey.txt.dec > /dev/null 2>&1

# Try to encrypt a message larger than the key
echo -n "This message is longer than 5 bytes" | ./bin/otp -c smallkeytest --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - error when message exceeds key size"
else
  echo "     ! ${RED}FAIL${NC} - should error when message exceeds key size"
  exit -1
fi

# Verify keychain was not modified (sequence should still be 0)
OUTPUT=$(./bin/otp --show-contact smallkeytest)
echo "$OUTPUT" | grep -q "EncryptedSequence: 0"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - keychain not modified on error"
else
  echo "     ! ${RED}FAIL${NC} - keychain was modified on error"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: message spanning multiple streaming chunks must not leak or
#  consume key material when it exceeds the key size (regression test - the
#  streaming loop processes input in 4MB chunks; a message that only
#  overflows the key on a *later* chunk must not have already emitted
#  earlier chunks or advanced the key offset/sequence, otherwise those key
#  bytes would silently look "unused" while their ciphertext was already
#  produced, allowing them to be reused for a later message)
# -----------------------------------------------------------------------------

echo "     Testing multi-chunk message exceeding key size does not consume key..."

# Key spans more than one 4MB streaming chunk
dd if=/dev/urandom of=multichunk_key.txt bs=1M count=5 2>/dev/null
dd if=/dev/urandom of=multichunk_key.txt.dec bs=1 count=$(wc -c < multichunk_key.txt) 2>/dev/null
./bin/otp --add-contact multichunktest multichunk_key.txt multichunk_key.txt.dec > /dev/null 2>&1

# Message also spans multiple 4MB chunks and exceeds the 5MB key only once
# the second chunk is read - with the bug, the first 4MB chunk would already
# have been written to real output before the overflow on the second chunk
# was detected, leaking usable ciphertext for key bytes that still look
# "unused" to the keychain.
dd if=/dev/urandom of=bigmsg.txt bs=1M count=10 2>/dev/null

./bin/otp -c multichunktest --encrypt < bigmsg.txt > multichunk_partial_output.bin 2>/dev/null
RC=$?
if [ $RC -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - error when multi-chunk message exceeds key size"
else
  echo "     ! ${RED}FAIL${NC} - should error when multi-chunk message exceeds key size"
  exit -1
fi

# Critical check: a failed attempt must not have emitted ANY ciphertext to
# the real output, even partially. This is the actual regression: earlier
# chunks were previously flushed to output before the overflow on a later
# chunk was discovered, leaking ciphertext for key bytes the keychain still
# considered unused.
PARTIAL_SIZE=$(wc -c < multichunk_partial_output.bin | tr -d ' ')
if [ "$PARTIAL_SIZE" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - no partial ciphertext leaked to output on failure"
else
  echo "     ! ${RED}FAIL${NC} - $PARTIAL_SIZE bytes of ciphertext leaked to output despite failure (key reuse risk)"
  exit -1
fi

# Key material must be completely untouched by the failed attempt
OUTPUT=$(./bin/otp --show-contact multichunktest)
echo "$OUTPUT" | grep -q "EncryptedSequence: 0"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - sequence not incremented after multi-chunk failure"
else
  echo "     ! ${RED}FAIL${NC} - sequence incremented after multi-chunk failure (key was consumed)"
  exit -1
fi

echo "$OUTPUT" | grep -q "EncryptionKeyOffset: 0"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - encryption key offset unchanged after multi-chunk failure"
else
  echo "     ! ${RED}FAIL${NC} - encryption key offset advanced after multi-chunk failure (key bytes leaked)"
  exit -1
fi

# Encrypt a small message that fits within the key. If the earlier failed
# attempt had leaked/consumed the first chunk's key bytes, this message
# would now be encrypted with the wrong (already-used) key bytes instead of
# the key's true, untouched starting bytes.
dd if=/dev/urandom of=smallmsg.txt bs=1 count=100 2>/dev/null
./bin/otp -c multichunktest --encrypt < smallmsg.txt > multichunk_cipher.bin 2>/dev/null

dd if=multichunk_key.txt of=multichunk_key_prefix.txt bs=1 count=100 2>/dev/null
./bin/otp multichunk_key_prefix.txt < smallmsg.txt > expected_cipher.bin 2>/dev/null

cmp -s multichunk_cipher.bin expected_cipher.bin
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - key material was not leaked or desynced by the failed multi-chunk attempt"
else
  echo "     ! ${RED}FAIL${NC} - encrypted output does not match expected ciphertext (key was reused/desynced)"
  exit -1
fi

rm -f multichunk_key.txt multichunk_key_prefix.txt bigmsg.txt smallmsg.txt multichunk_partial_output.bin
rm -f multichunk_cipher.bin expected_cipher.bin multichunk_key_prefix.txt.*.next

# -----------------------------------------------------------------------------
#  test error: missing --encrypt or --decrypt flag
# -----------------------------------------------------------------------------

echo -n "test" | ./bin/otp -c enctest > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - ${GREEN}PASS${NC} - error when missing --encrypt/--decrypt flag"
else
  echo "     ! ${RED}FAIL${NC} - should error when missing --encrypt/--decrypt flag"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test multiple operations on same contact
# -----------------------------------------------------------------------------

echo "     Testing multiple operations..."

# Second encryption should use the next part of the key
PLAIN_MSG2="Second message"
echo -n "$PLAIN_MSG2" > test_plain2.txt
./bin/otp -c enctest --encrypt < test_plain2.txt > test_cipher2.bin 2>/dev/null

OUTPUT=$(./bin/otp --show-contact enctest)
echo "$OUTPUT" | grep -q "EncryptedSequence: 2"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - sequence incremented on second operation"
else
  echo "     ! ${RED}FAIL${NC} - sequence not incremented correctly on second operation"
  exit -1
fi

# Verify offset increased by the second message length
EXPECTED_OFFSET=$((13 + 14))
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: $EXPECTED_OFFSET"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - offset updated correctly after multiple operations"
else
  echo "     ! ${RED}FAIL${NC} - offset not updated correctly after multiple operations"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test full round-trip with separate keychains (simulating Alice and Bob)
# -----------------------------------------------------------------------------

echo "     Testing full round-trip with separate keychains..."

# Simulate two independent machines: with per-contact metadata files,
# Alice's "bob" contact and Bob's "alice" contact have different names
# and could technically coexist in one shared .keychain/ - but a real
# round-trip test should model Alice and Bob as genuinely separate
# people, each with their own keychain directory, not sharing storage at
# all. Each gets its own working directory (and therefore its own
# .keychain/).
OTP_BIN="$(pwd)/bin/otp"
rm -rf alice_home bob_home
mkdir -p alice_home bob_home

dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | "$OTP_BIN" --new-key-pair 1 alice bob > /dev/null 2>&1
rm tmpkey

# Alice receives her half of the key pair, Bob receives his
mv encryption_alice.txt decryption_alice.txt alice_home/
mv encryption_bob.txt decryption_bob.txt bob_home/

(cd alice_home && "$OTP_BIN" --add-contact bob encryption_alice.txt decryption_alice.txt > /dev/null 2>&1)
(cd bob_home && "$OTP_BIN" --add-contact alice encryption_bob.txt decryption_bob.txt > /dev/null 2>&1)

# Test 1: Alice encrypts to Bob
ALICE_MSG="Top secret message from Alice"
(cd alice_home && echo -n "$ALICE_MSG" | "$OTP_BIN" -c bob --encrypt 2>/dev/null > ../roundtrip_msg1.bin)

# Test 2: Bob decrypts Alice's message
BOB_DECRYPTED=$(cd bob_home && cat ../roundtrip_msg1.bin | "$OTP_BIN" -c alice --decrypt 2>/dev/null)

if [ "$BOB_DECRYPTED" = "$ALICE_MSG" ]; then
  echo "     - ${GREEN}PASS${NC} - round-trip Alice->Bob successful"
else
  echo "     ! ${RED}FAIL${NC} - round-trip failed (expected '$ALICE_MSG', got '$BOB_DECRYPTED')"
  exit 1
fi

# Test 3: Bob encrypts reply to Alice
BOB_MSG="Confirmed. Reply from Bob."
(cd bob_home && echo -n "$BOB_MSG" | "$OTP_BIN" -c alice --encrypt 2>/dev/null > ../roundtrip_msg2.bin)

# Test 4: Alice decrypts Bob's reply
ALICE_DECRYPTED=$(cd alice_home && cat ../roundtrip_msg2.bin | "$OTP_BIN" -c bob --decrypt 2>/dev/null)

if [ "$ALICE_DECRYPTED" = "$BOB_MSG" ]; then
  echo "     - ${GREEN}PASS${NC} - round-trip Bob->Alice successful"
else
  echo "     ! ${RED}FAIL${NC} - round-trip failed (expected '$BOB_MSG', got '$ALICE_DECRYPTED')"
  exit 1
fi

# Verify both parties have correct sequence numbers
ALICE_ENC_SEQ=$(cd alice_home && "$OTP_BIN" -sc bob 2>/dev/null | grep "EncryptedSequence:" | awk '{print $2}')
ALICE_DEC_SEQ=$(cd alice_home && "$OTP_BIN" -sc bob 2>/dev/null | grep "DecryptedSequence:" | awk '{print $2}')
BOB_ENC_SEQ=$(cd bob_home && "$OTP_BIN" -sc alice 2>/dev/null | grep "EncryptedSequence:" | awk '{print $2}')
BOB_DEC_SEQ=$(cd bob_home && "$OTP_BIN" -sc alice 2>/dev/null | grep "DecryptedSequence:" | awk '{print $2}')

# Alice sent 1, received 1; Bob sent 1, received 1
if [ "$ALICE_ENC_SEQ" = "1" ] && [ "$ALICE_DEC_SEQ" = "1" ] && [ "$BOB_ENC_SEQ" = "1" ] && [ "$BOB_DEC_SEQ" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - both parties have correct sequence numbers"
else
  echo "     ! ${RED}FAIL${NC} - sequence numbers incorrect (Alice enc:$ALICE_ENC_SEQ dec:$ALICE_DEC_SEQ, Bob enc:$BOB_ENC_SEQ dec:$BOB_DEC_SEQ)"
  exit 1
fi

echo "     - ${GREEN}PASS${NC} - full bidirectional communication verified"

rm -rf alice_home bob_home
rm -f roundtrip_msg1.bin roundtrip_msg2.bin

# -----------------------------------------------------------------------------
#  contact names are used verbatim to build filenames
#
#  A contact's name becomes the filename of its key files, its .meta file,
#  its .lock file and its pending artifacts - all of which are meant to
#  stay inside .keychain/. An unvalidated name containing a path separator
#  escaped that directory entirely, and could also make two distinct
#  contacts share one lock file, silently defeating mutual exclusion.
# -----------------------------------------------------------------------------

echo "     Testing contact name validation..."

dd if=/dev/urandom of=kc_namekey.txt bs=1 count=100 2>/dev/null

./bin/otp --add-contact "../escaped" kc_namekey.txt kc_namekey.txt > /dev/null 2>kc_name_stderr.log
RC=$?
if [ $RC -ne 0 ] && [ ! -f "../escaped.meta" ] && [ ! -f "../escaped_enc.key" ]; then
  echo "     - ${GREEN}PASS${NC} - a name containing a path separator is rejected and writes nothing"
else
  echo "     ! ${RED}FAIL${NC} - a path-traversing contact name was accepted (exit $RC)"
  rm -f ../escaped.meta ../escaped_enc.key ../escaped_dec.key
  exit 1
fi

grep -q "Invalid contact name" kc_name_stderr.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the rejection says why"
else
  echo "     ! ${RED}FAIL${NC} - no explanation given for the rejected name"
  cat kc_name_stderr.log
  exit 1
fi

REJECTED=0
for BAD in ".." "." "a/b" "a\\b" "a:b" "a=b" "" "a*b"; do
  ./bin/otp --add-contact "$BAD" kc_namekey.txt kc_namekey.txt > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "     ! ${RED}FAIL${NC} - invalid contact name '$BAD' was accepted"
    exit 1
  fi
  REJECTED=$((REJECTED + 1))
done
echo "     - ${GREEN}PASS${NC} - all $REJECTED invalid name forms rejected"

# Ordinary names, including spaces and dots, must still work
dd if=/dev/urandom of=kc_namekey.txt.dec bs=1 count=$(wc -c < kc_namekey.txt) 2>/dev/null
./bin/otp --add-contact "jane.doe smith" kc_namekey.txt kc_namekey.txt.dec > /dev/null 2>&1
if [ $? -eq 0 ] && [ -f ".keychain/jane.doe smith.meta" ]; then
  echo "     - ${GREEN}PASS${NC} - ordinary names with dots and spaces are still accepted"
else
  echo "     ! ${RED}FAIL${NC} - a legitimate contact name was rejected"
  exit 1
fi

# -----------------------------------------------------------------------------
#  key material must never be created world-readable
# -----------------------------------------------------------------------------

echo "     Testing key file permissions..."

PERM_ENC=$(ls -l ".keychain/jane.doe smith_enc.key" | cut -c1-10)
PERM_DEC=$(ls -l ".keychain/jane.doe smith_dec.key" | cut -c1-10)

if [ "$PERM_ENC" = "-rw-------" ] && [ "$PERM_DEC" = "-rw-------" ]; then
  echo "     - ${GREEN}PASS${NC} - copied key files are created 0600, not world-readable"
else
  echo "     ! ${RED}FAIL${NC} - key files have permissions $PERM_ENC / $PERM_DEC (expected -rw-------)"
  exit 1
fi

./bin/otp --remove-contact "jane.doe smith" > /dev/null 2>&1

# -----------------------------------------------------------------------------
#  a contact needs both key files or neither - one is an error
#
#  Accepting a single key file and quietly creating a keyless contact
#  would report success while leaving the user believing their key was
#  loaded.
# -----------------------------------------------------------------------------

echo "     Testing key file argument handling..."

./bin/otp --add-contact halfkeyed kc_namekey.txt > /dev/null 2>kc_half_stderr.log
RC=$?
# Count only the contact's own artifacts (.meta / .key), not its .lock
# file: acquiring the per-contact lock legitimately creates <name>.lock
# even for an add that is then rejected, exactly as encrypt/decrypt/remove
# do, and that empty lock file is deliberately persistent (see
# remove_contact in src/keychain.c). "Creating nothing" means creating no
# contact, i.e. no .meta or .key.
CREATED=$(ls .keychain/ 2>/dev/null | grep "^halfkeyed" | grep -vc '\.lock$')

if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a single key file argument is rejected, creating nothing"
else
  echo "     ! ${RED}FAIL${NC} - a single key file argument was accepted (exit $RC, $CREATED files)"
  exit 1
fi

# Both forms that are legitimate must still work
dd if=/dev/urandom of=kc_namekey.txt.dec bs=1 count=$(wc -c < kc_namekey.txt) 2>/dev/null
./bin/otp --add-contact bothkeys kc_namekey.txt kc_namekey.txt.dec > /dev/null 2>&1
RC1=$?
./bin/otp --add-contact nokeys > /dev/null 2>&1
RC2=$?
if [ $RC1 -eq 0 ] && [ $RC2 -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - both-keys and no-keys forms still accepted"
else
  echo "     ! ${RED}FAIL${NC} - a legitimate add-contact form was rejected ($RC1 / $RC2)"
  exit 1
fi

# Failures must exit 1, not a raw -1 surfacing as 255
dd if=/dev/urandom of=kc_namekey.txt.dec bs=1 count=$(wc -c < kc_namekey.txt) 2>/dev/null
./bin/otp --add-contact bothkeys kc_namekey.txt kc_namekey.txt.dec > /dev/null 2>&1
DUP_RC=$?
./bin/otp --remove-contact definitely_not_here > /dev/null 2>&1
RM_RC=$?
if [ $DUP_RC -eq 1 ] && [ $RM_RC -eq 1 ]; then
  echo "     - ${GREEN}PASS${NC} - failing contact commands exit 1"
else
  echo "     ! ${RED}FAIL${NC} - unexpected exit codes (duplicate add $DUP_RC, missing remove $RM_RC)"
  exit 1
fi

./bin/otp --remove-contact bothkeys > /dev/null 2>&1
./bin/otp --remove-contact nokeys > /dev/null 2>&1
rm -f kc_namekey.txt kc_name_stderr.log kc_half_stderr.log

# -----------------------------------------------------------------------------
#  a contact must not be given the same one-time pad for both directions
#
#  If the encryption and decryption keys hold the same bytes, the range
#  that encrypts an outgoing message is the same range that decrypts an
#  incoming one - two messages covered by one pad. Comparison is by
#  content, so a copy under a different name is caught too.
# -----------------------------------------------------------------------------

echo "     Testing rejection of identical encryption/decryption keys..."

dd if=/dev/urandom of=kc_dupkey.txt bs=1 count=500 2>/dev/null
cp kc_dupkey.txt kc_dupcopy.txt
dd if=/dev/urandom of=kc_otherkey.txt bs=1 count=500 2>/dev/null

./bin/otp --add-contact samefile kc_dupkey.txt kc_dupkey.txt > /dev/null 2>kc_dup1.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^samefile" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - the same file passed twice is rejected, creating nothing"
else
  echo "     ! ${RED}FAIL${NC} - the same key file was accepted for both directions (exit $RC)"
  exit 1
fi

./bin/otp --add-contact samebytes kc_dupkey.txt kc_dupcopy.txt > /dev/null 2>kc_dup2.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^samebytes" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a copy under a different name is rejected too"
else
  echo "     ! ${RED}FAIL${NC} - identical key content under two names was accepted (exit $RC)"
  exit 1
fi

grep -q "contain the same key material" kc_dup2.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal explains why one pad cannot serve both directions"
else
  echo "     ! ${RED}FAIL${NC} - refusal not explained"
  cat kc_dup2.log
  exit 1
fi

./bin/otp --add-contact distinctkeys kc_dupkey.txt kc_otherkey.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - two genuinely different keys are still accepted"
else
  echo "     ! ${RED}FAIL${NC} - a legitimate key pair was rejected"
  exit 1
fi

# -----------------------------------------------------------------------------
#  the identical-key check must fail closed, not open
#
#  If the comparison itself cannot run (out of memory, out of file
#  descriptors), that proves nothing about the keys - reporting it as
#  "no overlap" would let two byte-identical pads through, breaking the
#  pad silently and forever. OTP_TEST_FAIL_KEY_COMPARE simulates the
#  comparison's resource acquisitions failing; even a legitimate,
#  genuinely distinct pair must then be refused, since the tool cannot
#  tell it apart from an identical one.
# -----------------------------------------------------------------------------

echo "     Testing that a failed key comparison refuses rather than accepts..."

# This section needs its own pads: kc_dupkey/kc_otherkey are now installed
# for 'distinctkeys', and supplying an already-installed pad to a second
# contact is itself refused (see the cross-contact reuse section below).
dd if=/dev/urandom of=kc_fckey1.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_fckey2.txt bs=1 count=500 2>/dev/null

OTP_TEST_FAIL_KEY_COMPARE=1 ./bin/otp --add-contact failclosed kc_fckey1.txt kc_fckey2.txt > /dev/null 2>kc_failcmp.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^failclosed" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - an uncomparable key pair is refused, creating nothing"
else
  echo "     ! ${RED}FAIL${NC} - keys were accepted although the overlap check never ran (exit $RC)"
  exit 1
fi

grep -q "Could not compare" kc_failcmp.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal names the comparison failure, not a key overlap"
else
  echo "     ! ${RED}FAIL${NC} - refusal reason not explained"
  cat kc_failcmp.log
  exit 1
fi

./bin/otp --add-contact failclosed kc_fckey1.txt kc_fckey2.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the same pair is accepted once the comparison can run"
else
  echo "     ! ${RED}FAIL${NC} - pair still refused without the injected failure"
  exit 1
fi
./bin/otp --remove-contact failclosed > /dev/null 2>&1
rm -f kc_failcmp.log kc_fckey1.txt kc_fckey2.txt

# -----------------------------------------------------------------------------
#  re-using a contact name must warn about already-spent key material
#
#  Once a contact is removed its key files are gone, so nothing remains to
#  compare a freshly supplied key against. Supplying the ORIGINAL key from
#  generation would restart at offset 0 over already-spent bytes.
# -----------------------------------------------------------------------------

echo "     Testing the warning when a contact name is re-used..."

printf 'consume a little' | ./bin/otp -c distinctkeys --encrypt > /dev/null 2>&1
./bin/otp --remove-contact distinctkeys > /dev/null 2>&1

# Rotating a re-used name onto genuinely fresh keys is the legitimate case
# the warning exists to permit. Re-supplying the spent ORIGINAL is no longer
# merely warned about - the spent-key registry refuses it outright (tested
# in its own section below) - so the rotation here uses new pads.
dd if=/dev/urandom of=kc_rotkey1.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_rotkey2.txt bs=1 count=500 2>/dev/null
./bin/otp --add-contact distinctkeys kc_rotkey1.txt kc_rotkey2.txt > /dev/null 2>kc_reuse.log
RC=$?
grep -q "has been used on this keychain before" kc_reuse.log
G=$?
if [ $RC -eq 0 ] && [ $G -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - re-adding a previously used name warns but still succeeds"
else
  echo "     ! ${RED}FAIL${NC} - name re-use not warned about (exit $RC, warn $G)"
  cat kc_reuse.log
  exit 1
fi

grep -q "ORIGINAL copies" kc_reuse.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the warning names the actual hazard"
else
  echo "     ! ${RED}FAIL${NC} - the warning does not explain the hazard"
  exit 1
fi

# A name never used before must stay silent. Its keys must be fresh ones:
# any key-material overlap with installed or spent pads would (rightly)
# produce output of its own and hide what this test measures.
dd if=/dev/urandom of=kc_quietkey1.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_quietkey2.txt bs=1 count=500 2>/dev/null
./bin/otp --add-contact neverseen kc_quietkey1.txt kc_quietkey2.txt > /dev/null 2>kc_quiet.log
if [ ! -s kc_quiet.log ]; then
  echo "     - ${GREEN}PASS${NC} - a fresh contact name produces no warning"
else
  echo "     ! ${RED}FAIL${NC} - a fresh name produced output"
  cat kc_quiet.log
  exit 1
fi

./bin/otp --remove-contact distinctkeys > /dev/null 2>&1
./bin/otp --remove-contact neverseen > /dev/null 2>&1
rm -f kc_dupkey.txt kc_dupcopy.txt kc_otherkey.txt kc_dup1.log kc_dup2.log kc_reuse.log kc_quiet.log
rm -f kc_rotkey1.txt kc_rotkey2.txt kc_quietkey1.txt kc_quietkey2.txt

# -----------------------------------------------------------------------------
#  overlap hidden inside a key must be detected (interior overlap)
#
#  A pad trimmed at both ends, or two windows cut from the same pad, share
#  key material without either file being a prefix or suffix of the other.
#  Alignment-only comparison passes such pairs as distinct; the overlap
#  check must instead find either file's opening bytes wherever they sit
#  inside the other.
# -----------------------------------------------------------------------------

echo "     Testing detection of overlap hidden inside a key (interior overlap)..."

dd if=/dev/urandom of=kc_bigpad.txt bs=1024 count=300 2>/dev/null
# A slice cut from the middle: neither the front nor the tail of the pad
dd if=kc_bigpad.txt of=kc_midslice.txt bs=1024 skip=100 count=100 2>/dev/null

./bin/otp --add-contact interiortest kc_bigpad.txt kc_midslice.txt > /dev/null 2>kc_interior.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^interiortest" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a slice cut from the middle of a pad is rejected against that pad"
else
  echo "     ! ${RED}FAIL${NC} - an interior slice of the same pad was accepted (exit $RC)"
  exit 1
fi

grep -q "appears inside" kc_interior.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal identifies the overlap even though neither end lines up"
else
  echo "     ! ${RED}FAIL${NC} - interior overlap not identified as such"
  cat kc_interior.log
  exit 1
fi

# Two windows sharing only a middle stretch: winA is bytes 0-200K, winB is
# bytes 100K-300K. Neither contains the other and no aligned prefix/suffix
# matches, yet 100K of pad is common to both.
dd if=kc_bigpad.txt of=kc_winA.txt bs=1024 count=200 2>/dev/null
dd if=kc_bigpad.txt of=kc_winB.txt bs=1024 skip=100 count=200 2>/dev/null

./bin/otp --add-contact interiortest kc_winA.txt kc_winB.txt > /dev/null 2>&1
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^interiortest" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - two windows sharing only a middle stretch are rejected"
else
  echo "     ! ${RED}FAIL${NC} - two overlapping windows of one pad were accepted (exit $RC)"
  exit 1
fi

# Control: two genuinely independent pads of the same sizes still pass
dd if=/dev/urandom of=kc_indep1.txt bs=1024 count=300 2>/dev/null
dd if=/dev/urandom of=kc_indep2.txt bs=1024 count=100 2>/dev/null
./bin/otp --add-contact interiortest kc_indep1.txt kc_indep2.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - two genuinely independent pads are still accepted"
else
  echo "     ! ${RED}FAIL${NC} - independent pads were refused by the interior check"
  exit 1
fi
./bin/otp --remove-contact interiortest > /dev/null 2>&1
rm -f kc_bigpad.txt kc_midslice.txt kc_winA.txt kc_winB.txt kc_indep1.txt kc_indep2.txt kc_interior.log

# -----------------------------------------------------------------------------
#  key material installed for one contact must not be accepted for another
#
#  The same pad under two contacts is consumed twice from its own start -
#  two different messages covered by the same bytes. The one legitimate
#  shape is the mirrored pair (new enc = existing dec and vice versa),
#  which is how one machine operates both endpoints of its own pads for
#  loopback testing; that is allowed but warned about.
# -----------------------------------------------------------------------------

echo "     Testing that key material installed for another contact is rejected..."

dd if=/dev/urandom of=kc_ccA.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_ccB.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_ccC.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_ccD.txt bs=1 count=500 2>/dev/null

./bin/otp --add-contact ccfirst kc_ccA.txt kc_ccB.txt > /dev/null 2>&1

./bin/otp --add-contact ccsecond kc_ccA.txt kc_ccC.txt > /dev/null 2>kc_cc1.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^ccsecond" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a pad already serving as another contact's encryption key is rejected"
else
  echo "     ! ${RED}FAIL${NC} - the same pad was installed for two contacts (exit $RC)"
  exit 1
fi

grep -q "contact 'ccfirst'" kc_cc1.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal names the contact already holding that pad"
else
  echo "     ! ${RED}FAIL${NC} - refusal does not say which contact holds the pad"
  cat kc_cc1.log
  exit 1
fi

./bin/otp --add-contact ccsecond kc_ccC.txt kc_ccB.txt > /dev/null 2>&1
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^ccsecond" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - the decryption direction is checked too"
else
  echo "     ! ${RED}FAIL${NC} - a shared decryption pad was accepted (exit $RC)"
  exit 1
fi

# The tail of an installed pad is what a ".next" file or a partially
# consumed key looks like - handing it to a second contact is the same
# overlap and must be caught across contacts, not only within one pair.
dd if=kc_ccA.txt of=kc_ccA_tail.txt bs=1 skip=100 2>/dev/null
./bin/otp --add-contact ccsecond kc_ccA_tail.txt kc_ccC.txt > /dev/null 2>&1
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^ccsecond" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a remainder of an installed pad is rejected across contacts too"
else
  echo "     ! ${RED}FAIL${NC} - a tail of an installed pad was accepted for another contact (exit $RC)"
  exit 1
fi

# The mirrored pair is the other endpoint of the same pads: allowed, since
# that is how loopback testing in one directory works, but warned about.
./bin/otp --add-contact ccmirror kc_ccB.txt kc_ccA.txt > /dev/null 2>kc_ccmirror.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the mirrored pair of an existing contact is allowed for loopback use"
else
  echo "     ! ${RED}FAIL${NC} - the mirrored (other-endpoint) pair was refused"
  cat kc_ccmirror.log
  exit 1
fi

grep -q "other endpoint" kc_ccmirror.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the mirror add warns that it looks like the pad's other endpoint"
else
  echo "     ! ${RED}FAIL${NC} - no other-endpoint warning for the mirrored pair"
  cat kc_ccmirror.log
  exit 1
fi

# Genuinely fresh keys must still be accepted while the others are installed
./bin/otp --add-contact ccsecond kc_ccC.txt kc_ccD.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - unrelated key material is still accepted alongside them"
else
  echo "     ! ${RED}FAIL${NC} - unrelated keys were refused by the cross-contact check"
  exit 1
fi

./bin/otp --remove-contact ccfirst > /dev/null 2>&1
./bin/otp --remove-contact ccmirror > /dev/null 2>&1
./bin/otp --remove-contact ccsecond > /dev/null 2>&1
rm -f kc_ccA.txt kc_ccB.txt kc_ccC.txt kc_ccD.txt kc_ccA_tail.txt kc_cc1.log kc_ccmirror.log

# -----------------------------------------------------------------------------
#  a removed contact's spent original must not come back under a new name
#
#  Removing a contact deletes its key files, so a later add has nothing to
#  compare against - re-supplying the ORIGINAL file from key generation
#  would restart at offset 0 over bytes that already encrypted messages.
#  The spent-heads registry closes this: the first time a key's opening
#  bytes are consumed, their fingerprint is recorded durably, and any
#  later candidate containing those bytes is recognized whatever the
#  contact is now called. The partially consumed remainder (which no
#  longer contains the spent head) must remain acceptable - it is exactly
#  what a user SHOULD carry over.
# -----------------------------------------------------------------------------

echo "     Testing that a removed contact's spent original is refused under a new name..."

dd if=/dev/urandom of=kc_spentkey.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=kc_spentdec.txt bs=1 count=500 2>/dev/null
./bin/otp --add-contact spentowner kc_spentkey.txt kc_spentdec.txt > /dev/null 2>&1

# Recording the fingerprint must fail closed: if it cannot be written, the
# operation aborts before any key material is spent.
printf 'x' | OTP_TEST_FAIL_SPENT_RECORD=1 ./bin/otp -c spentowner --encrypt > /dev/null 2>&1
RC=$?
OFFSET=$(./bin/otp --show-contact spentowner | grep "EncryptionKeyOffset:" | awk '{print $2}')
if [ $RC -ne 0 ] && [ "$OFFSET" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - a failed fingerprint record aborts before any key is spent"
else
  echo "     ! ${RED}FAIL${NC} - key was spent although its fingerprint could not be recorded (exit $RC, offset $OFFSET)"
  exit 1
fi

# Spend the first 14 bytes of the pad for real, then remove the contact
printf 'spend this pad' | ./bin/otp -c spentowner --encrypt > /dev/null 2>&1
./bin/otp --remove-contact spentowner > /dev/null 2>&1

# The original file still exists outside the keychain. Under a brand-new
# name nothing else ties it to the removed contact - only the registry can.
dd if=/dev/urandom of=kc_freshdec.txt bs=1 count=500 2>/dev/null
./bin/otp --add-contact freshname kc_spentkey.txt kc_freshdec.txt > /dev/null 2>kc_spent.log
RC=$?
CREATED=$(ls .keychain/ 2>/dev/null | grep "^freshname" | grep -vc '\.lock$')
if [ $RC -ne 0 ] && [ "$CREATED" = "0" ]; then
  echo "     - ${GREEN}PASS${NC} - the spent original is rejected even under a fresh contact name"
else
  echo "     ! ${RED}FAIL${NC} - a spent original key was re-installed under a new name (exit $RC)"
  exit 1
fi

grep -q "already spent" kc_spent.log
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the refusal explains that the key material was already spent here"
else
  echo "     ! ${RED}FAIL${NC} - refusal does not explain the spent-key hazard"
  cat kc_spent.log
  exit 1
fi

# The remainder - the original minus its 14 consumed bytes - is the safe
# carry-over and must still be accepted.
dd if=kc_spentkey.txt of=kc_spentremainder.txt bs=1 skip=14 2>/dev/null
./bin/otp --add-contact freshname kc_spentremainder.txt kc_freshdec.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - the partially consumed remainder is still accepted"
else
  echo "     ! ${RED}FAIL${NC} - the legitimate remainder was refused"
  exit 1
fi
./bin/otp --remove-contact freshname > /dev/null 2>&1

# The removed contact's OTHER key was never consumed - re-using it is safe
# and must not be blocked by the registry.
dd if=/dev/urandom of=kc_newenc.txt bs=1 count=500 2>/dev/null
./bin/otp --add-contact unspentreuse kc_newenc.txt kc_spentdec.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - a never-consumed key from the removed contact is still accepted"
else
  echo "     ! ${RED}FAIL${NC} - an unspent key was refused as if it had been consumed"
  exit 1
fi
./bin/otp --remove-contact unspentreuse > /dev/null 2>&1
rm -f kc_spentkey.txt kc_spentdec.txt kc_freshdec.txt kc_spentremainder.txt kc_newenc.txt kc_spent.log

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf .keychain
rm -f encryption_testalice.txt decryption_testalice.txt
rm -f encryption_testbob.txt decryption_testbob.txt
rm -f encryption_enctest.txt decryption_enctest.txt
rm -f encryption_dectest.txt decryption_dectest.txt
rm -f encryption_alice.txt decryption_alice.txt
rm -f encryption_bob.txt decryption_bob.txt
rm -f smallkey.txt roundtrip_msg1.bin roundtrip_msg2.bin

echo ""
exit 0
