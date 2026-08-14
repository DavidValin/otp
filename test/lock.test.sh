#!/bin/sh

# Per-contact locking tests.
#
# encrypt/decrypt for the same contact must be mutually exclusive: two
# processes racing on the same contact would otherwise each independently
# read the same starting key offset and each produce individually
# "valid", individually verified output - the crash-safety staging
# mechanism in src/commit.c has no way to detect that, since nothing
# about either process's own work is wrong in isolation. Only true mutual
# exclusion (contact_lock_acquire/release in src/commit.c, backed by
# flock() on a per-contact lock file) prevents it.

rm -f keychain.txt
rm -rf .keychain

echo ""
echo "   - Per-contact locking"

# -----------------------------------------------------------------------------
#  the lock file must live alongside the rest of that contact's keychain
#  data, in .keychain/, not somewhere else
# -----------------------------------------------------------------------------

echo "     Testing lock file location..."

dd if=/dev/urandom of=lock_key1.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact locktest1 lock_key1.txt lock_key1.txt > /dev/null 2>&1

printf 'trigger lock creation' | ./bin/otp -c locktest1 --encrypt > /dev/null 2>/dev/null

if [ -f ".keychain/locktest1.lock" ]; then
  echo "     - PASS - lock file created at .keychain/<contact>.lock"
else
  echo "     ! FAIL - lock file not found at the expected location"
  ls .keychain/ 2>&1
  exit 1
fi

rm -f lock_key1.txt
rm -f keychain.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  two real concurrent processes encrypting for the SAME contact must be
#  serialized: both must succeed, and the key ranges they each consume
#  must be disjoint (no process may read/use a key range the other one
#  also used)
# -----------------------------------------------------------------------------

echo "     Testing concurrent encrypt for the same contact does not reuse key material..."

dd if=/dev/urandom of=lock_key2.txt bs=1 count=4000 2>/dev/null
./bin/otp --add-contact locktest2 lock_key2.txt lock_key2.txt > /dev/null 2>&1

printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > lock_plainA.txt
printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' > lock_plainB.txt

./bin/otp -c locktest2 --encrypt < lock_plainA.txt > lock_cipherA.bin 2>lock_stderrA.log &
PIDA=$!
./bin/otp -c locktest2 --encrypt < lock_plainB.txt > lock_cipherB.bin 2>lock_stderrB.log &
PIDB=$!
wait $PIDA
RCA=$?
wait $PIDB
RCB=$?

if [ $RCA -eq 0 ] && [ $RCB -eq 0 ]; then
  echo "     - PASS - both concurrent operations completed successfully"
else
  echo "     ! FAIL - a concurrent operation failed (A=$RCA B=$RCB)"
  cat lock_stderrA.log
  cat lock_stderrB.log
  exit 1
fi

LENA=$(wc -c < lock_plainA.txt | tr -d ' ')
LENB=$(wc -c < lock_plainB.txt | tr -d ' ')

# Both messages are the same length here, so exactly one of {0, LENA} must
# be the offset A's ciphertext was really produced with, and likewise for
# B - and they must land on DIFFERENT offsets from each other.
find_offset() {
  # args: plainfile cipherfile -> prints the offset that reproduces cipherfile, or "NONE"
  PLAINFILE=$1
  CIPHERFILE=$2
  LEN=$(wc -c < "$PLAINFILE" | tr -d ' ')
  for OFF in 0 "$LEN"; do
    dd if=lock_key2.txt of=lock_slice.tmp bs=1 skip="$OFF" count="$LEN" 2>/dev/null
    ./bin/otp lock_slice.tmp < "$PLAINFILE" > lock_expected.tmp 2>/dev/null
    rm -f lock_slice.tmp lock_slice.tmp.*.next
    if cmp -s lock_expected.tmp "$CIPHERFILE"; then
      rm -f lock_expected.tmp
      echo "$OFF"
      return
    fi
  done
  rm -f lock_expected.tmp
  echo "NONE"
}

OFFA=$(find_offset lock_plainA.txt lock_cipherA.bin)
OFFB=$(find_offset lock_plainB.txt lock_cipherB.bin)

if [ "$OFFA" = "NONE" ] || [ "$OFFB" = "NONE" ]; then
  echo "     ! FAIL - a ciphertext does not correspond to any expected key range at all"
  exit 1
fi

if [ "$OFFA" != "$OFFB" ]; then
  echo "     - PASS - the two concurrent messages used disjoint key ranges ($OFFA and $OFFB)"
else
  echo "     ! FAIL - both concurrent messages used the SAME key range ($OFFA) - key reuse!"
  exit 1
fi

TOTAL=$((LENA + LENB))
OUTPUT=$(./bin/otp --show-contact locktest2)
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: $TOTAL"
if [ $? -eq 0 ]; then
  echo "     - PASS - final key offset accounts for both messages exactly once each"
else
  echo "     ! FAIL - final key offset does not match the sum of both messages"
  echo "$OUTPUT"
  exit 1
fi

echo "$OUTPUT" | grep -q "EncryptedSequence: 2"
if [ $? -eq 0 ]; then
  echo "     - PASS - sequence counted both messages exactly once each"
else
  echo "     ! FAIL - sequence does not reflect both messages"
  exit 1
fi

rm -f lock_key2.txt lock_plainA.txt lock_plainB.txt lock_cipherA.bin lock_cipherB.bin
rm -f lock_stderrA.log lock_stderrB.log

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -f keychain.txt
rm -rf .keychain

echo ""
exit 0
