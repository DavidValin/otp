#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --status tests.
#
# --status <contact> [--porcelain] reports one contact's per-direction
# state, verified from the disk files themselves: the key file's physical
# size (the authority on remaining key), the .meta declarations, the
# pending-artifact scan it shares with crash recovery (commit_classify),
# and the kept last-payload copies. It must be strictly read-only: no
# sweep, no discard, no metadata self-heal - the keychain directory must
# be byte-identical before and after (the empty per-contact .lock file,
# which every command creates on first touch, is created before the
# snapshots below so it can never differ).
#
# Exit codes under test: 0 clean, 4 redelivery pending, 5 delivery
# confirmation outstanding, 6 key material rolled back, 1 error.

rm -rf .keychain
rm -f st_*

echo ""
echo "   - --status: disk-verified contact state"

# Two loopback contacts sharing mirrored pads: what stsend encrypts,
# strecv decrypts.
dd if=/dev/urandom of=st_k1 bs=1 count=4096 2>/dev/null
dd if=/dev/urandom of=st_k2 bs=1 count=4096 2>/dev/null
./bin/otp --add-contact stsend st_k1 st_k2 > /dev/null 2>&1
./bin/otp --add-contact strecv st_k2 st_k1 > /dev/null 2>&1

# Byte-level snapshot of every keychain file, for the read-only proofs.
keychain_snapshot() {
  find .keychain -type f | LC_ALL=C sort | xargs cksum
}

# -----------------------------------------------------------------------------
#  unknown contact fails with exit 1
# -----------------------------------------------------------------------------

echo "     Testing errors..."

./bin/otp --status nobody --porcelain > st_out 2> st_err
if [ $? -eq 1 ] && grep -q "not found" st_err; then
  echo "     - ${GREEN}PASS${NC} - unknown contact: exit 1"
else
  echo "     ! ${RED}FAIL${NC} - unknown contact did not exit 1"
  exit 1
fi

# -----------------------------------------------------------------------------
#  fresh contact: everything at baseline, exit 0
# -----------------------------------------------------------------------------

echo "     Testing baseline state..."

./bin/otp --status stsend --porcelain > st_out 2>/dev/null
RC=$?
if [ $RC -eq 0 ] &&
   grep -q '^contact=stsend$' st_out &&
   grep -q '^enc_sequence=0$' st_out &&
   grep -q '^enc_key_remaining=4096$' st_out &&
   grep -q '^enc_meta_state=consistent$' st_out &&
   grep -q '^enc_redelivery_pending=0$' st_out &&
   grep -q '^enc_ack_outstanding=0$' st_out &&
   grep -q '^dec_sequence=0$' st_out &&
   grep -q '^dec_key_remaining=4096$' st_out &&
   grep -q '^dec_ack_outstanding=0$' st_out; then
  echo "     - ${GREEN}PASS${NC} - fresh contact: exit 0, all porcelain fields at baseline"
else
  echo "     ! ${RED}FAIL${NC} - fresh contact status wrong (exit $RC)"
  cat st_out
  exit 1
fi

# a contact added without keys still reports, with zero key remaining
./bin/otp --add-contact stempty > /dev/null 2>&1
./bin/otp --status stempty --porcelain > st_out 2>/dev/null
if [ $? -eq 0 ] && grep -q '^enc_key_remaining=0$' st_out; then
  echo "     - ${GREEN}PASS${NC} - keyless contact: exit 0, zero key remaining"
else
  echo "     ! ${RED}FAIL${NC} - keyless contact status wrong"
  exit 1
fi
./bin/otp --remove-contact stempty > /dev/null 2>&1

# -----------------------------------------------------------------------------
#  after an encrypt: ack outstanding (exit 5), sequence and key reflect it
# -----------------------------------------------------------------------------

echo "     Testing ack-outstanding after an operation..."

dd if=/dev/urandom of=st_plain1 bs=100 count=1 2>/dev/null
OTP_TEST_NO_TTY=1 ./bin/otp -c stsend --encrypt < st_plain1 > st_c1 2>/dev/null
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: first encrypt failed"
  exit 1
fi
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
RC=$?
if [ $RC -eq 5 ] &&
   grep -q '^enc_sequence=1$' st_out &&
   grep -q '^enc_key_remaining=3996$' st_out &&
   grep -q '^enc_ack_outstanding=1$' st_out &&
   grep -q '^enc_redelivery_pending=0$' st_out &&
   grep -q '^dec_ack_outstanding=0$' st_out; then
  echo "     - ${GREEN}PASS${NC} - after encrypt: exit 5, enc_ack_outstanding=1, key/sequence updated"
else
  echo "     ! ${RED}FAIL${NC} - post-encrypt status wrong (exit $RC)"
  cat st_out
  exit 1
fi

# the decrypt direction of the receiving contact, symmetrically
OTP_TEST_NO_TTY=1 ./bin/otp -c strecv --decrypt < st_c1 > st_p1 2>/dev/null
if ! cmp -s st_p1 st_plain1; then
  echo "     ! ${RED}FAIL${NC} - test setup: decrypt round-trip failed"
  exit 1
fi
./bin/otp --status strecv --porcelain > st_out 2>/dev/null
RC=$?
if [ $RC -eq 5 ] &&
   grep -q '^dec_sequence=1$' st_out &&
   grep -q '^dec_ack_outstanding=1$' st_out &&
   grep -q '^enc_ack_outstanding=0$' st_out; then
  echo "     - ${GREEN}PASS${NC} - after decrypt: exit 5, dec_ack_outstanding=1 on the receiving side"
else
  echo "     ! ${RED}FAIL${NC} - post-decrypt status wrong (exit $RC)"
  cat st_out
  exit 1
fi

# -----------------------------------------------------------------------------
#  --status is strictly read-only: keychain byte-identical before and after
# -----------------------------------------------------------------------------

echo "     Testing --status is read-only..."

keychain_snapshot > st_snap1
./bin/otp --status stsend --porcelain > /dev/null 2>&1
./bin/otp --status stsend > /dev/null 2>&1
./bin/otp --status strecv --porcelain > /dev/null 2>&1
keychain_snapshot > st_snap2
if cmp -s st_snap1 st_snap2; then
  echo "     - ${GREEN}PASS${NC} - keychain byte-identical after both output modes"
else
  echo "     ! ${RED}FAIL${NC} - --status modified the keychain"
  diff st_snap1 st_snap2
  exit 1
fi

# human-readable mode names the contact and the kept copy
./bin/otp --status stsend > st_out 2>/dev/null
if grep -q "Contact: stsend" st_out && grep -q "awaiting delivery confirmation" st_out; then
  echo "     - ${GREEN}PASS${NC} - human-readable mode reports the same state"
else
  echo "     ! ${RED}FAIL${NC} - human-readable output missing expected lines"
  cat st_out
  exit 1
fi

# -----------------------------------------------------------------------------
#  crash window 1 (uncommitted artifact): NOT reported as redelivery, and
#  the stale artifact is left for the next operation to discard
# -----------------------------------------------------------------------------

echo "     Testing crash windows..."

dd if=/dev/urandom of=st_plain2 bs=80 count=1 2>/dev/null
OTP_TEST_CRASH_POINT=after_pending_publish OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c stsend --encrypt < st_plain2 > /dev/null 2>/dev/null
if ! ls .keychain/stsend_enc_pending_seq*.bin > /dev/null 2>&1; then
  echo "     ! ${RED}FAIL${NC} - test setup: crash left no pending artifact"
  exit 1
fi
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
RC=$?
# the -y gate removed the previous copy before the crash, so nothing is
# outstanding and nothing will be redelivered: exit 0
if [ $RC -eq 0 ] && grep -q '^enc_redelivery_pending=0$' st_out; then
  echo "     - ${GREEN}PASS${NC} - uncommitted artifact: no redelivery reported (exit 0)"
else
  echo "     ! ${RED}FAIL${NC} - uncommitted artifact misreported (exit $RC)"
  cat st_out
  exit 1
fi
if ls .keychain/stsend_enc_pending_seq*.bin > /dev/null 2>&1; then
  echo "     - ${GREEN}PASS${NC} - stale artifact untouched by --status (cleanup stays with the next operation)"
else
  echo "     ! ${RED}FAIL${NC} - --status removed the stale artifact"
  exit 1
fi

# the next real encrypt discards the stale artifact and proceeds normally
OTP_ASSUME_DELIVERED=1 ./bin/otp -c stsend --encrypt < st_plain2 > /dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo "     ! ${RED}FAIL${NC} - test setup: encrypt after stale artifact failed"
  exit 1
fi

# -----------------------------------------------------------------------------
#  crash window 2 (key committed, .meta stale): redelivery pending, exit 4,
#  metadata reported consistent (the artifact's tag finishes it), and the
#  artifact again untouched by --status
# -----------------------------------------------------------------------------

dd if=/dev/urandom of=st_plain3 bs=50 count=1 2>/dev/null
OTP_TEST_CRASH_POINT=after_key_publish OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c stsend --encrypt < st_plain3 > /dev/null 2>/dev/null
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
RC=$?
if [ $RC -eq 4 ] &&
   grep -q '^enc_redelivery_pending=1$' st_out &&
   grep -q '^enc_sequence=3$' st_out &&
   grep -q '^enc_meta_state=consistent$' st_out; then
  echo "     - ${GREEN}PASS${NC} - committed crash: exit 4, redelivery pending, artifact's sequence adopted"
else
  echo "     ! ${RED}FAIL${NC} - committed crash misreported (exit $RC)"
  cat st_out
  exit 1
fi
if ls .keychain/stsend_enc_pending_seq*.bin > /dev/null 2>&1; then
  echo "     - ${GREEN}PASS${NC} - committed artifact untouched by --status"
else
  echo "     ! ${RED}FAIL${NC} - --status removed the committed artifact"
  exit 1
fi

# human mode announces what the next operation will do
./bin/otp --status stsend > st_out 2>/dev/null
if grep -q "REDELIVER message #3" st_out; then
  echo "     - ${GREEN}PASS${NC} - human-readable mode announces the pending redelivery"
else
  echo "     ! ${RED}FAIL${NC} - human-readable mode missing the redelivery notice"
  cat st_out
  exit 1
fi

# a redelivery run exits 3 with the recovered ciphertext, and the status
# afterwards drops back to ack-outstanding (exit 5)
printf 'new input, must be ignored' | OTP_ASSUME_DELIVERED=1 \
  ./bin/otp -c stsend --encrypt > st_c3 2>/dev/null
RC=$?
if [ $RC -eq 3 ] && [ "$(wc -c < st_c3 | tr -d ' ')" != "0" ]; then
  echo "     - ${GREEN}PASS${NC} - redelivery run: exit 3 with the recovered ciphertext"
else
  echo "     ! ${RED}FAIL${NC} - redelivery run broken after --status (exit $RC)"
  exit 1
fi
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
if [ $? -eq 5 ] && grep -q '^enc_redelivery_pending=0$' st_out && grep -q '^enc_ack_outstanding=1$' st_out; then
  echo "     - ${GREEN}PASS${NC} - after redelivery: exit 5, back to ack-outstanding"
else
  echo "     ! ${RED}FAIL${NC} - post-redelivery status wrong"
  cat st_out
  exit 1
fi

# -----------------------------------------------------------------------------
#  metadata drift: behind is reported (not healed); rolled back is exit 6
# -----------------------------------------------------------------------------

echo "     Testing metadata drift detection..."

# shrink the key file by 10 bytes: metadata is now merely behind
KEYSIZE=$(wc -c < .keychain/stsend_enc.key | tr -d ' ')
dd if=.keychain/stsend_enc.key of=st_shrunk bs=1 count=$((KEYSIZE - 10)) 2>/dev/null
mv st_shrunk .keychain/stsend_enc.key
cp .keychain/stsend.meta st_meta_before
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
if grep -q '^enc_meta_state=meta_behind$' st_out && cmp -s .keychain/stsend.meta st_meta_before; then
  echo "     - ${GREEN}PASS${NC} - lagging metadata reported as meta_behind and NOT healed by --status"
else
  echo "     ! ${RED}FAIL${NC} - meta_behind misreported, or --status modified the .meta file"
  cat st_out
  exit 1
fi

# grow the key file past what the metadata declares: rolled-back material
printf 'ROLLEDBACKBYTESROLLEDBACK' >> .keychain/stsend_enc.key
./bin/otp --status stsend --porcelain > st_out 2>/dev/null
RC=$?
if [ $RC -eq 6 ] && grep -q '^enc_meta_state=rolled_back$' st_out; then
  echo "     - ${GREEN}PASS${NC} - rolled-back key material: exit 6, rolled_back reported"
else
  echo "     ! ${RED}FAIL${NC} - rollback misreported (exit $RC)"
  cat st_out
  exit 1
fi
./bin/otp --status stsend 2>/dev/null | grep -q "ROLLED BACK"
if [ $? -eq 0 ]; then
  echo "     - ${GREEN}PASS${NC} - human-readable mode warns about the rollback"
else
  echo "     ! ${RED}FAIL${NC} - human-readable mode missing the rollback warning"
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain
rm -f st_*
echo ""
exit 0
