#!/bin/sh

# Keychain tests for OTP

# Clean up any existing test keychain
rm -f keychain.txt

echo ""
echo "   - Keychain functionality"

# -----------------------------------------------------------------------------
#  test add contact
# -----------------------------------------------------------------------------

echo "     Testing add contact..."

./bin/otp --add-contact alice > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - add contact succeeded"
else
  echo "     ! FAIL - add contact failed"
  exit -1
fi

if test -f "keychain.txt"; then
  echo "     - PASS - keychain.txt file was created"
else
  echo "     ! FAIL - keychain.txt file was NOT created"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test has contact
# -----------------------------------------------------------------------------

echo "     Testing has contact..."

./bin/otp --has-contact alice > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - has contact found alice"
else
  echo "     ! FAIL - has contact did not find alice"
  exit -1
fi

./bin/otp --has-contact bob > /dev/null
if [ $? -ne 0 ]; then
  echo "     - PASS - has contact correctly reports bob doesn't exist"
else
  echo "     ! FAIL - has contact incorrectly found bob"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test list contacts
# -----------------------------------------------------------------------------

echo "     Testing list contacts..."

OUTPUT=$(./bin/otp --list-contacts)
echo "$OUTPUT" | grep -q "alice"
if [ $? -eq 0 ]; then
  echo "     - PASS - list contacts shows alice"
else
  echo "     ! FAIL - list contacts does not show alice"
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
  echo "     - PASS - list contacts shows all three contacts"
else
  echo "     ! FAIL - list contacts missing some contacts"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test show contact
# -----------------------------------------------------------------------------

echo "     Testing show contact..."

OUTPUT=$(./bin/otp --show-contact alice)
echo "$OUTPUT" | grep -q "Contact: alice"
if [ $? -eq 0 ]; then
  echo "     - PASS - show contact displays alice"
else
  echo "     ! FAIL - show contact does not display alice correctly"
  exit -1
fi

# Check that keys are masked
echo "$OUTPUT" | grep -q "\*\*\*\*\*\*\*"
if [ $? -eq 0 ]; then
  echo "     - PASS - show contact masks keys"
else
  echo "     ! FAIL - show contact does not mask keys"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test remove contact
# -----------------------------------------------------------------------------

echo "     Testing remove contact..."

./bin/otp --remove-contact bob > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - remove contact succeeded"
else
  echo "     ! FAIL - remove contact failed"
  exit -1
fi

./bin/otp --has-contact bob > /dev/null
if [ $? -ne 0 ]; then
  echo "     - PASS - bob was successfully removed"
else
  echo "     ! FAIL - bob still exists after removal"
  exit -1
fi

# Verify alice and charlie still exist
./bin/otp --has-contact alice > /dev/null
ALICE_EXISTS=$?
./bin/otp --has-contact charlie > /dev/null
CHARLIE_EXISTS=$?

if [ $ALICE_EXISTS -eq 0 ] && [ $CHARLIE_EXISTS -eq 0 ]; then
  echo "     - PASS - other contacts remain after removal"
else
  echo "     ! FAIL - other contacts were incorrectly affected"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test duplicate contact
# -----------------------------------------------------------------------------

echo "     Testing duplicate contact prevention..."

./bin/otp --add-contact alice > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - PASS - duplicate contact correctly rejected"
else
  echo "     ! FAIL - duplicate contact was allowed"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test short options
# -----------------------------------------------------------------------------

echo "     Testing short options..."

./bin/otp -ac dave > /dev/null
./bin/otp -hc dave > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - short option -ac and -hc work"
else
  echo "     ! FAIL - short options don't work"
  exit -1
fi

OUTPUT=$(./bin/otp -lc)
echo "$OUTPUT" | grep -q "dave"
if [ $? -eq 0 ]; then
  echo "     - PASS - short option -lc works"
else
  echo "     ! FAIL - short option -lc doesn't work"
  exit -1
fi

OUTPUT=$(./bin/otp -sc dave)
echo "$OUTPUT" | grep -q "Contact: dave"
if [ $? -eq 0 ]; then
  echo "     - PASS - short option -sc works"
else
  echo "     ! FAIL - short option -sc doesn't work"
  exit -1
fi

./bin/otp -rc dave > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - short option -rc works"
else
  echo "     ! FAIL - short option -rc doesn't work"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test persistence
# -----------------------------------------------------------------------------

echo "     Testing persistence..."

# The keychain should already be saved with alice and charlie
# Verify by checking the file directly
grep -q "Name=alice" keychain.txt
ALICE_IN_FILE=$?
grep -q "Name=charlie" keychain.txt
CHARLIE_IN_FILE=$?

if [ $ALICE_IN_FILE -eq 0 ] && [ $CHARLIE_IN_FILE -eq 0 ]; then
  echo "     - PASS - contacts persisted to file"
else
  echo "     ! FAIL - contacts not properly persisted"
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
  echo "     ! FAIL - key pair generation failed"
  exit -1
fi

# Add contact with keys
./bin/otp --add-contact testcontact encryption_testalice.txt decryption_testalice.txt > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - add contact with keys succeeded"
else
  echo "     ! FAIL - add contact with keys failed"
  exit -1
fi

# Verify contact was added
./bin/otp --has-contact testcontact > /dev/null
if [ $? -eq 0 ]; then
  echo "     - PASS - contact with keys exists"
else
  echo "     ! FAIL - contact with keys was not added"
  exit -1
fi

# Verify keys were loaded
OUTPUT=$(./bin/otp --show-contact testcontact)
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* ([1-9][0-9]* bytes)"
ENC_KEY_LOADED=$?
echo "$OUTPUT" | grep -q "DecryptionKey: \*\*\*\*\*\*\* ([1-9][0-9]* bytes)"
DEC_KEY_LOADED=$?

if [ $ENC_KEY_LOADED -eq 0 ] && [ $DEC_KEY_LOADED -eq 0 ]; then
  echo "     - PASS - keys were loaded correctly"
else
  echo "     ! FAIL - keys were not loaded properly"
  exit -1
fi

# Test that key size is correct (1MB = 1048576 bytes)
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* (1048576 bytes)"
if [ $? -eq 0 ]; then
  echo "     - PASS - encryption key size is correct"
else
  echo "     ! FAIL - encryption key size is incorrect"
  exit -1
fi

echo "$OUTPUT" | grep -q "DecryptionKey: \*\*\*\*\*\*\* (1048576 bytes)"
if [ $? -eq 0 ]; then
  echo "     - PASS - decryption key size is correct"
else
  echo "     ! FAIL - decryption key size is incorrect"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test encryption with contact
# -----------------------------------------------------------------------------

echo "     Testing encryption with contact..."

# Create a contact with keys for testing
rm -f keychain.txt
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | ./bin/otp --new-key-pair 1 enctest dectest > /dev/null 2>&1
rm tmpkey

./bin/otp --add-contact enctest encryption_enctest.txt decryption_enctest.txt > /dev/null 2>&1

# Encrypt a message
PLAIN_MSG="Hello, World!"
CIPHER=$(echo -n "$PLAIN_MSG" | ./bin/otp -c enctest --encrypt 2>/dev/null)

if [ $? -eq 0 ]; then
  echo "     - PASS - encryption with contact succeeded"
else
  echo "     ! FAIL - encryption with contact failed"
  exit -1
fi

# Verify cipher text is not the same as plain text
if [ "$CIPHER" != "$PLAIN_MSG" ]; then
  echo "     - PASS - cipher text differs from plain text"
else
  echo "     ! FAIL - cipher text same as plain text"
  exit -1
fi

# Verify key offset was updated
OUTPUT=$(./bin/otp --show-contact enctest)
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: 13"
if [ $? -eq 0 ]; then
  echo "     - PASS - encryption key offset updated correctly"
else
  echo "     ! FAIL - encryption key offset not updated correctly"
  exit -1
fi

# Verify sequence was incremented
echo "$OUTPUT" | grep -q "Sequence: 1"
if [ $? -eq 0 ]; then
  echo "     - PASS - sequence incremented correctly"
else
  echo "     ! FAIL - sequence not incremented"
  exit -1
fi

# Verify LastMessageSentAt was set
echo "$OUTPUT" | grep -q -v "LastMessageSentAt: never"
if [ $? -eq 0 ]; then
  echo "     - PASS - LastMessageSentAt timestamp set"
else
  echo "     ! FAIL - LastMessageSentAt not set"
  exit -1
fi

# Verify remaining key size
EXPECTED_REMAINING=$((1048576 - 13))
echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* ($EXPECTED_REMAINING bytes)"
if [ $? -eq 0 ]; then
  echo "     - PASS - remaining encryption key size correct"
else
  echo "     ! FAIL - remaining encryption key size incorrect"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test decryption with contact
# -----------------------------------------------------------------------------

echo "     Testing decryption with contact..."

# Create Bob with matching keys (Alice's decryption = Bob's encryption)
./bin/otp --add-contact dectest encryption_dectest.txt decryption_dectest.txt > /dev/null 2>&1

# Decrypt the cipher using dectest's decryption key
DECRYPTED=$(echo -n "$CIPHER" | ./bin/otp -c dectest --decrypt 2>/dev/null)

if [ $? -eq 0 ]; then
  echo "     - PASS - decryption with contact succeeded"
else
  echo "     ! FAIL - decryption with contact failed"
  exit -1
fi

# Verify decrypted text matches original
if [ "$DECRYPTED" = "$PLAIN_MSG" ]; then
  echo "     - PASS - decrypted text matches original plain text"
else
  echo "     ! FAIL - decrypted text does not match (expected '$PLAIN_MSG', got '$DECRYPTED')"
  exit -1
fi

# Verify decryption key offset was updated
OUTPUT=$(./bin/otp --show-contact dectest)
echo "$OUTPUT" | grep -q "DecryptionKeyOffset: 13"
if [ $? -eq 0 ]; then
  echo "     - PASS - decryption key offset updated correctly"
else
  echo "     ! FAIL - decryption key offset not updated correctly"
  exit -1
fi

# Verify LastMessageReceivedAt was set
echo "$OUTPUT" | grep -q -v "LastMessageReceivedAt: never"
if [ $? -eq 0 ]; then
  echo "     - PASS - LastMessageReceivedAt timestamp set"
else
  echo "     ! FAIL - LastMessageReceivedAt not set"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: contact not found
# -----------------------------------------------------------------------------

echo "     Testing error cases..."

echo -n "test" | ./bin/otp -c nonexistent --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - PASS - error on nonexistent contact"
else
  echo "     ! FAIL - should error on nonexistent contact"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: contact with empty key
# -----------------------------------------------------------------------------

./bin/otp --add-contact emptykey > /dev/null 2>&1
echo -n "test" | ./bin/otp -c emptykey --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - PASS - error on empty encryption key"
else
  echo "     ! FAIL - should error on empty encryption key"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: message too large for key
# -----------------------------------------------------------------------------

# Create contact with very small key
dd if=/dev/urandom of=smallkey.txt bs=1 count=5 2>/dev/null
./bin/otp --add-contact smallkeytest smallkey.txt smallkey.txt > /dev/null 2>&1

# Try to encrypt a message larger than the key
echo -n "This message is longer than 5 bytes" | ./bin/otp -c smallkeytest --encrypt > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - PASS - error when message exceeds key size"
else
  echo "     ! FAIL - should error when message exceeds key size"
  exit -1
fi

# Verify keychain was not modified (sequence should still be 0)
OUTPUT=$(./bin/otp --show-contact smallkeytest)
echo "$OUTPUT" | grep -q "Sequence: 0"
if [ $? -eq 0 ]; then
  echo "     - PASS - keychain not modified on error"
else
  echo "     ! FAIL - keychain was modified on error"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test error: missing --encrypt or --decrypt flag
# -----------------------------------------------------------------------------

echo -n "test" | ./bin/otp -c enctest > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "     - PASS - error when missing --encrypt/--decrypt flag"
else
  echo "     ! FAIL - should error when missing --encrypt/--decrypt flag"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test multiple operations on same contact
# -----------------------------------------------------------------------------

echo "     Testing multiple operations..."

# Second encryption should use the next part of the key
PLAIN_MSG2="Second message"
CIPHER2=$(echo -n "$PLAIN_MSG2" | ./bin/otp -c enctest --encrypt 2>/dev/null)

OUTPUT=$(./bin/otp --show-contact enctest)
echo "$OUTPUT" | grep -q "Sequence: 2"
if [ $? -eq 0 ]; then
  echo "     - PASS - sequence incremented on second operation"
else
  echo "     ! FAIL - sequence not incremented correctly on second operation"
  exit -1
fi

# Verify offset increased by the second message length
EXPECTED_OFFSET=$((13 + 14))
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: $EXPECTED_OFFSET"
if [ $? -eq 0 ]; then
  echo "     - PASS - offset updated correctly after multiple operations"
else
  echo "     ! FAIL - offset not updated correctly after multiple operations"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test full round-trip with separate keychains (simulating Alice and Bob)
# -----------------------------------------------------------------------------

echo "     Testing full round-trip with separate keychains..."

# Clean up and generate fresh keys
rm -f keychain.txt alice_keychain.txt bob_keychain.txt
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | ./bin/otp --new-key-pair 1 alice bob > /dev/null 2>&1
rm tmpkey

# Alice's keychain setup
cp keychain.txt alice_keychain.txt 2>/dev/null || touch alice_keychain.txt
./bin/otp --add-contact bob encryption_alice.txt decryption_alice.txt > /dev/null 2>&1
cp keychain.txt alice_keychain.txt

# Bob's keychain setup
cp alice_keychain.txt keychain.txt 2>/dev/null || touch keychain.txt
rm keychain.txt
touch keychain.txt
./bin/otp --add-contact alice encryption_bob.txt decryption_bob.txt > /dev/null 2>&1
cp keychain.txt bob_keychain.txt

# Test 1: Alice encrypts to Bob
cp alice_keychain.txt keychain.txt
ALICE_MSG="Top secret message from Alice"
echo -n "$ALICE_MSG" | ./bin/otp -c bob --encrypt 2>/dev/null > roundtrip_msg1.bin
cp keychain.txt alice_keychain.txt

# Test 2: Bob decrypts Alice's message
cp bob_keychain.txt keychain.txt
BOB_DECRYPTED=$(cat roundtrip_msg1.bin | ./bin/otp -c alice --decrypt 2>/dev/null)
cp keychain.txt bob_keychain.txt

if [ "$BOB_DECRYPTED" = "$ALICE_MSG" ]; then
  echo "     - PASS - round-trip Alice->Bob successful"
else
  echo "     ! FAIL - round-trip failed (expected '$ALICE_MSG', got '$BOB_DECRYPTED')"
  exit -1
fi

# Test 3: Bob encrypts reply to Alice
cp bob_keychain.txt keychain.txt
BOB_MSG="Confirmed. Reply from Bob."
echo -n "$BOB_MSG" | ./bin/otp -c alice --encrypt 2>/dev/null > roundtrip_msg2.bin
cp keychain.txt bob_keychain.txt

# Test 4: Alice decrypts Bob's reply
cp alice_keychain.txt keychain.txt
ALICE_DECRYPTED=$(cat roundtrip_msg2.bin | ./bin/otp -c bob --decrypt 2>/dev/null)
cp keychain.txt alice_keychain.txt

if [ "$ALICE_DECRYPTED" = "$BOB_MSG" ]; then
  echo "     - PASS - round-trip Bob->Alice successful"
else
  echo "     ! FAIL - round-trip failed (expected '$BOB_MSG', got '$ALICE_DECRYPTED')"
  exit -1
fi

# Verify both parties have same sequence numbers
cp alice_keychain.txt keychain.txt
ALICE_SEQ=$(./bin/otp -sc bob 2>/dev/null | grep "Sequence:" | awk '{print $2}')
cp bob_keychain.txt keychain.txt
BOB_SEQ=$(./bin/otp -sc alice 2>/dev/null | grep "Sequence:" | awk '{print $2}')

if [ "$ALICE_SEQ" = "2" ] && [ "$BOB_SEQ" = "2" ]; then
  echo "     - PASS - both parties have correct sequence numbers"
else
  echo "     ! FAIL - sequence numbers incorrect (Alice: $ALICE_SEQ, Bob: $BOB_SEQ)"
  exit -1
fi

echo "     - PASS - full bidirectional communication verified"

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -f keychain.txt alice_keychain.txt bob_keychain.txt
rm -f encryption_testalice.txt decryption_testalice.txt
rm -f encryption_testbob.txt decryption_testbob.txt
rm -f encryption_enctest.txt decryption_enctest.txt
rm -f encryption_dectest.txt decryption_dectest.txt
rm -f encryption_alice.txt decryption_alice.txt
rm -f encryption_bob.txt decryption_bob.txt
rm -f smallkey.txt roundtrip_msg1.bin roundtrip_msg2.bin

echo ""
exit 0
