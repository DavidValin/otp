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

rm -rf .keychain

echo ""
echo "   - Per-contact locking"

# -----------------------------------------------------------------------------
#  the lock file must live alongside the rest of that contact's keychain
#  data, in .keychain/, not somewhere else
# -----------------------------------------------------------------------------

echo "     Testing lock file location..."

dd if=/dev/urandom of=lock_key1.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=lock_key1.txt.dec bs=1 count=$(wc -c < lock_key1.txt) 2>/dev/null
./bin/otp --add-contact locktest1 lock_key1.txt lock_key1.txt.dec > /dev/null 2>&1

printf 'trigger lock creation' | ./bin/otp -c locktest1 --encrypt > /dev/null 2>/dev/null

if [ -f ".keychain/locktest1.lock" ]; then
  echo "     - ${GREEN}PASS${NC} - lock file created at .keychain/<contact>.lock"
else
  echo "     ! ${RED}FAIL${NC} - lock file not found at the expected location"
  ls .keychain/ 2>&1
  exit 1
fi

rm -f lock_key1.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  two real concurrent processes encrypting for the SAME contact must be
#  serialized: both must succeed, and the key ranges they each consume
#  must be disjoint (no process may read/use a key range the other one
#  also used)
# -----------------------------------------------------------------------------

echo "     Testing concurrent encrypt for the same contact does not reuse key material..."

dd if=/dev/urandom of=lock_key2.txt bs=1 count=4000 2>/dev/null
dd if=/dev/urandom of=lock_key2.txt.dec bs=1 count=$(wc -c < lock_key2.txt) 2>/dev/null
./bin/otp --add-contact locktest2 lock_key2.txt lock_key2.txt.dec > /dev/null 2>&1

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
  echo "     - ${GREEN}PASS${NC} - both concurrent operations completed successfully"
else
  echo "     ! ${RED}FAIL${NC} - a concurrent operation failed (A=$RCA B=$RCB)"
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
  echo "     ! ${RED}FAIL${NC} - a ciphertext does not correspond to any expected key range at all"
  exit 1
fi

if [ "$OFFA" != "$OFFB" ]; then
  echo "     - ${GREEN}PASS${NC} - the two concurrent messages used disjoint key ranges ($OFFA and $OFFB)"
else
  echo "     ! ${RED}FAIL${NC} - both concurrent messages used the SAME key range ($OFFA) - key reuse!"
  exit 1
fi

TOTAL=$((LENA + LENB))
OUTPUT=$(./bin/otp --show-contact locktest2)
echo "$OUTPUT" | grep -q "EncryptionKeyOffset: $TOTAL"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - final key offset accounts for both messages exactly once each"
else
  echo "     ! ${RED}FAIL${NC} - final key offset does not match the sum of both messages"
  echo "$OUTPUT"
  exit 1
fi

echo "$OUTPUT" | grep -q "EncryptedSequence: 2"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - sequence counted both messages exactly once each"
else
  echo "     ! ${RED}FAIL${NC} - sequence does not reflect both messages"
  exit 1
fi

rm -f lock_key2.txt lock_plainA.txt lock_plainB.txt lock_cipherA.bin lock_cipherB.bin
rm -f lock_stderrA.log lock_stderrB.log

# -----------------------------------------------------------------------------
#  the same must hold for concurrent DECRYPT
#
#  Decryption consumes its own key file through the same code path, and
#  two racing decrypts would each read the same starting offset just as
#  two racing encrypts would. The lock is per contact and covers both
#  directions, so this must be serialized identically.
# -----------------------------------------------------------------------------

echo "     Testing concurrent decrypt for the same contact does not reuse key material..."

dd if=/dev/urandom of=lock_key3.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=lock_key3.txt.dec bs=1 count=$(wc -c < lock_key3.txt) 2>/dev/null
./bin/otp --add-contact locktest3 lock_key3.txt lock_key3.txt.dec > /dev/null 2>&1

# Same length, so exactly one of {0, LEN} is each output's true key range
printf 'ciphertext block AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > lock_ctA.bin
printf 'ciphertext block BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' > lock_ctB.bin

./bin/otp -c locktest3 --decrypt < lock_ctA.bin > lock_ptA.bin 2>lock_dstderrA.log &
DPIDA=$!
./bin/otp -c locktest3 --decrypt < lock_ctB.bin > lock_ptB.bin 2>lock_dstderrB.log &
DPIDB=$!
wait $DPIDA
DRCA=$?
wait $DPIDB
DRCB=$?

if [ $DRCA -eq 0 ] && [ $DRCB -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - both concurrent decrypts completed successfully"
else
  echo "     ! ${RED}FAIL${NC} - a concurrent decrypt failed (A=$DRCA B=$DRCB)"
  cat lock_dstderrA.log lock_dstderrB.log
  exit 1
fi

find_dec_offset() {
  CIPHERFILE=$1
  PLAINFILE=$2
  LEN=$(wc -c < "$CIPHERFILE" | tr -d ' ')
  for OFF in 0 "$LEN"; do
    dd if=lock_key3.txt.dec of=lock_dslice.tmp bs=1 skip="$OFF" count="$LEN" 2>/dev/null
    ./bin/otp lock_dslice.tmp < "$CIPHERFILE" > lock_dexpected.tmp 2>/dev/null
    rm -f lock_dslice.tmp lock_dslice.tmp.*.next
    if cmp -s lock_dexpected.tmp "$PLAINFILE"; then
      rm -f lock_dexpected.tmp
      echo "$OFF"
      return
    fi
  done
  rm -f lock_dexpected.tmp
  echo "NONE"
}

DOFFA=$(find_dec_offset lock_ctA.bin lock_ptA.bin)
DOFFB=$(find_dec_offset lock_ctB.bin lock_ptB.bin)

if [ "$DOFFA" = "NONE" ] || [ "$DOFFB" = "NONE" ]; then
  echo "     ! ${RED}FAIL${NC} - a plaintext does not correspond to any expected key range"
  exit 1
fi

if [ "$DOFFA" != "$DOFFB" ]; then
  echo "     - ${GREEN}PASS${NC} - the two concurrent decrypts used disjoint key ranges ($DOFFA and $DOFFB)"
else
  echo "     ! ${RED}FAIL${NC} - both concurrent decrypts used the SAME key range ($DOFFA) - key reuse!"
  exit 1
fi

DLEN=$(wc -c < lock_ctA.bin | tr -d ' ')
DTOTAL=$((DLEN + DLEN))
DOUT=$(./bin/otp --show-contact locktest3)
DSEQ=$(echo "$DOUT" | grep -c "DecryptedSequence: 2")
DOFF=$(echo "$DOUT" | grep -c "DecryptionKeyOffset: $DTOTAL")

if [ "$DSEQ" = "1" ] && [ "$DOFF" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - decryption key offset and sequence count both messages exactly once"
else
  echo "     ! ${RED}FAIL${NC} - decrypt bookkeeping wrong after concurrent operations"
  echo "$DOUT"
  exit 1
fi

rm -f lock_key3.txt lock_key3.txt.dec lock_ctA.bin lock_ctB.bin lock_ptA.bin lock_ptB.bin
rm -f lock_dstderrA.log lock_dstderrB.log

# -----------------------------------------------------------------------------
#  adding a contact must take the SAME per-contact lock as encrypt/decrypt
#
#  Adding a contact reads and writes that contact's own keychain state (the
#  existence check, the cross-contact overlap scan, the .meta write). Two
#  concurrent adds of one name would otherwise each pass their own "does
#  not exist" check and both write, silently losing the slower one; an add
#  could also race a remove of the same name. add_contact/
#  add_contact_with_keys therefore hold <contact>.lock across a fresh
#  reload and the write, exactly as encrypt/decrypt/remove do.
# -----------------------------------------------------------------------------

echo "     Testing that --add-contact honours the per-contact lock..."

rm -rf .keychain

dd if=/dev/urandom of=lock_addenc.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=lock_adddec.txt bs=1 count=500 2>/dev/null

# Deterministic proof that the add blocks on the contact lock: hold that
# exact lock file externally, then time how long an add is forced to wait.
# flock(1) is util-linux-only (absent on e.g. macOS), so skip gracefully
# where it is unavailable rather than fail on an unrelated platform.
if command -v flock > /dev/null 2>&1; then
  mkdir -p .keychain
  : > .keychain/addblock.lock

  # Hold addblock.lock exclusively for 3 seconds in the background.
  ( flock 9; sleep 3 ) 9> .keychain/addblock.lock &
  HOLDER=$!
  sleep 1  # let the holder acquire before we start the add

  START=$(date +%s)
  ./bin/otp --add-contact addblock lock_addenc.txt lock_adddec.txt > /dev/null 2>lock_addblock.log
  ADD_RC=$?
  END=$(date +%s)
  wait $HOLDER
  ELAPSED=$((END - START))

  if [ "$ELAPSED" -ge 2 ] && [ $ADD_RC -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - the add blocked on the held contact lock (~${ELAPSED}s) then completed"
  else
    echo "     ! ${RED}FAIL${NC} - the add did not wait for the contact lock (waited ${ELAPSED}s, exit $ADD_RC)"
    cat lock_addblock.log
    exit 1
  fi

  if [ -f ".keychain/addblock.meta" ]; then
    echo "     - ${GREEN}PASS${NC} - the contact was actually added once the lock was released"
  else
    echo "     ! ${RED}FAIL${NC} - the contact was not added after the lock cleared"
    exit 1
  fi
  rm -f lock_addblock.log
else
  echo "     - SKIP - flock(1) unavailable, cannot run the deterministic blocking check"
fi

rm -rf .keychain

# Concurrency outcome: fire many adds of the SAME name at once. With the
# lock exactly one may win (create the contact) and every other must see it
# already exists and fail cleanly - never a second silent "success" over
# the first, and never a corrupted contact.
echo "     Testing concurrent --add-contact of one name yields exactly one contact..."

dd if=/dev/urandom of=lock_racerenc.txt bs=1 count=500 2>/dev/null
dd if=/dev/urandom of=lock_racerdec.txt bs=1 count=500 2>/dev/null

rm -f lock_rc_*
i=0
while [ $i -lt 15 ]; do
  ( ./bin/otp --add-contact racer lock_racerenc.txt lock_racerdec.txt > /dev/null 2>&1
    echo $? > "lock_rc_$i" ) &
  i=$((i + 1))
done
wait

SUCCESS=$(cat lock_rc_* 2>/dev/null | grep -c '^0$')
METAS=$(ls .keychain/ 2>/dev/null | grep -c '^racer\.meta$')
KEYS=$(ls .keychain/ 2>/dev/null | grep -c '^racer_.*\.key$')

if [ "$SUCCESS" = "1" ]; then
  echo "     - ${GREEN}PASS${NC} - exactly one of 15 concurrent adds succeeded"
else
  echo "     ! ${RED}FAIL${NC} - $SUCCESS concurrent adds reported success (expected exactly 1) - a lost/duplicated add"
  exit 1
fi

if [ "$METAS" = "1" ] && [ "$KEYS" = "2" ]; then
  echo "     - ${GREEN}PASS${NC} - the keychain holds exactly one intact 'racer' (1 .meta, 2 .key files)"
else
  echo "     ! ${RED}FAIL${NC} - keychain state after the race is wrong ($METAS meta, $KEYS key files)"
  ls .keychain/
  exit 1
fi

# The single surviving contact must be usable: a round-trip through it works.
printf 'race survivor payload' | ./bin/otp -c racer --encrypt > lock_racecipher.bin 2>/dev/null
if [ -s lock_racecipher.bin ]; then
  echo "     - ${GREEN}PASS${NC} - the surviving contact encrypts normally"
else
  echo "     ! ${RED}FAIL${NC} - the surviving contact could not be used to encrypt"
  exit 1
fi

rm -f lock_racerenc.txt lock_racerdec.txt lock_rc_* lock_racecipher.bin
rm -f lock_addenc.txt lock_adddec.txt
rm -rf .keychain

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf .keychain

echo ""
exit 0
