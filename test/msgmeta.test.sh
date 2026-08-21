#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# These tests exercise the metadata layer, not the delivery-confirmation
# gate (see test/confirm.test.sh) - state the confirmation explicitly.
OTP_ASSUME_DELIVERED=1
export OTP_ASSUME_DELIVERED

# Per-message metadata layer tests.
#
# Every ciphertext opens with an encrypted binary metadata block
# (source_id / seq / offset - see the "Per-message metadata layer"
# comment in src/cipher.c). Decryption validates the block before any
# key material is consumed and rejects mismatches with a distinct exit
# code per combination:
#   1 invalid source_id            4 invalid source_id and seq
#   2 invalid seq                  7 invalid source_id and offset
#   3 invalid offset               6 invalid seq and offset
#                                  5 invalid source_id, seq and offset
# A rejected message must consume no key, emit no plaintext, and print
# the failure reasons to stderr with FAIL. The expected ciphertexts and
# the crafted invalid ones are built by test/xor.helper.sh, i.e. by
# different code than the code being verified.

. test/xor.helper.sh

rm -rf .keychain

echo ""
echo "   - Per-message metadata layer"

# -----------------------------------------------------------------------------
#  encrypt: the ciphertext is exactly metadata+plaintext XORed against
#  the key run after the 16-byte source_id chunk, and the bookkeeping
#  accounts for the whole contiguous range
# -----------------------------------------------------------------------------

echo "     Testing encrypt emits the metadata layer and accounts for its key range..."

dd if=/dev/urandom of=mm_enckey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=mm_enckey.txt.dec bs=1 count=1000 2>/dev/null
./bin/otp --add-contact mmsend mm_enckey.txt mm_enckey.txt.dec > /dev/null 2>&1

printf 'the quick brown fox jumps over the lazy dog' > mm_plain1.txt
PLEN=$(wc -c < mm_plain1.txt | tr -d ' ')

./bin/otp -c mmsend --encrypt < mm_plain1.txt > mm_cipher1.bin 2>/dev/null
RC=$?
make_cipher mm_enckey.txt 0 mm_plain1.txt 1 0 mm_expected1.bin

if [ $RC -eq 0 ] && cmp -s mm_cipher1.bin mm_expected1.bin; then
  echo "     - ${GREEN}PASS${NC} - ciphertext matches the independently computed metadata+message encryption"
else
  echo "     ! ${RED}FAIL${NC} - ciphertext does not match the expected metadata wire format (exit $RC)"
  exit 1
fi

CONSUMED1=$(meta_consumed_len "$PLEN" 1 0)
OUTPUT=$(./bin/otp --show-contact mmsend)
KEYLEFT=$(wc -c < .keychain/mmsend_enc.key | tr -d ' ')
if echo "$OUTPUT" | grep -q "EncryptionKeyOffset: $CONSUMED1" && [ "$KEYLEFT" = "$((1000 - CONSUMED1))" ]; then
  echo "     - ${GREEN}PASS${NC} - offset and key file account for source_id + metadata pad + message pad ($CONSUMED1 bytes)"
else
  echo "     ! ${RED}FAIL${NC} - key accounting is wrong (expected $CONSUMED1 consumed, key left $KEYLEFT)"
  echo "$OUTPUT"
  exit 1
fi

# -----------------------------------------------------------------------------
#  decrypt: a valid message is accepted, the metadata is stripped, and
#  the delivered plaintext is exactly the original
# -----------------------------------------------------------------------------

echo "     Testing decrypt validates the metadata and strips it from the output..."

dd if=/dev/urandom of=mm_key.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=mm_deckey.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact mmrecv mm_key.txt mm_deckey.txt > /dev/null 2>&1

make_cipher mm_deckey.txt 0 mm_plain1.txt 1 0 mm_c1.bin
./bin/otp -c mmrecv --decrypt < mm_c1.bin > mm_p1.txt 2>mm_err.log
RC=$?
if [ $RC -eq 0 ] && cmp -s mm_p1.txt mm_plain1.txt; then
  echo "     - ${GREEN}PASS${NC} - valid message accepted; plaintext is exactly the original, metadata stripped"
else
  echo "     ! ${RED}FAIL${NC} - valid message rejected or plaintext mangled (exit $RC)"
  cat mm_err.log
  exit 1
fi

DKEYLEFT=$(wc -c < .keychain/mmrecv_dec.key | tr -d ' ')
if [ "$DKEYLEFT" = "$((1000 - CONSUMED1))" ]; then
  echo "     - ${GREEN}PASS${NC} - decrypt consumed the same contiguous range as the sender ($CONSUMED1 bytes)"
else
  echo "     ! ${RED}FAIL${NC} - decrypt key accounting is wrong (key left $DKEYLEFT, expected $((1000 - CONSUMED1)))"
  exit 1
fi

# a second in-order message, whose offset needs the multi-byte encoding
printf 'second message, still in order' > mm_plain2.txt
make_cipher mm_deckey.txt "$CONSUMED1" mm_plain2.txt 2 "$CONSUMED1" mm_c2.bin
./bin/otp -c mmrecv --decrypt < mm_c2.bin > mm_p2.txt 2>mm_err.log
if [ $? -eq 0 ] && cmp -s mm_p2.txt mm_plain2.txt; then
  echo "     - ${GREEN}PASS${NC} - second message accepted at the advanced seq/offset"
else
  echo "     ! ${RED}FAIL${NC} - second in-order message was rejected"
  cat mm_err.log
  exit 1
fi

# a replay of message #1 must now fail everything: its source_id is no
# longer the key's next chunk, and both seq and offset are behind
cp .keychain/mmrecv_dec.key mm_deckey.snap
./bin/otp -c mmrecv --decrypt < mm_c1.bin > mm_replay.out 2>mm_err.log
RC=$?
if [ $RC -eq 5 ] && [ ! -s mm_replay.out ] && cmp -s .keychain/mmrecv_dec.key mm_deckey.snap &&
   grep -q "FAIL" mm_err.log; then
  echo "     - ${GREEN}PASS${NC} - replayed message rejected with exit 5, no key consumed, nothing emitted"
else
  echo "     ! ${RED}FAIL${NC} - replay must be rejected with exit 5 and consume nothing (exit $RC)"
  cat mm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  every invalid combination gets its documented exit code, prints FAIL
#  with the reasons to stderr, consumes no key, and emits nothing
# -----------------------------------------------------------------------------

echo "     Testing each invalid metadata combination exits with its own code..."

rm -rf .keychain
dd if=/dev/urandom of=mm_key.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=mm_deckey.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=mm_badsrc.bin bs=1 count=16 2>/dev/null
./bin/otp --add-contact mmrecv mm_key.txt mm_deckey.txt > /dev/null 2>&1
printf 'probe message' > mm_probe.txt

cp .keychain/mmrecv_dec.key mm_deckey.snap

# reject_case <expected_exit> <cipherfile> <label> <reason_pattern>...
reject_case() {
  RJ_EXPECT=$1; RJ_CIPHER=$2; RJ_LABEL=$3
  shift 3
  ./bin/otp -c mmrecv --decrypt < "$RJ_CIPHER" > mm_rj.out 2>mm_rj.err
  RJ_RC=$?
  if [ $RJ_RC -ne "$RJ_EXPECT" ]; then
    echo "     ! ${RED}FAIL${NC} - $RJ_LABEL must exit $RJ_EXPECT (got $RJ_RC)"
    cat mm_rj.err
    exit 1
  fi
  if [ -s mm_rj.out ]; then
    echo "     ! ${RED}FAIL${NC} - $RJ_LABEL must emit no plaintext"
    exit 1
  fi
  if ! cmp -s .keychain/mmrecv_dec.key mm_deckey.snap; then
    echo "     ! ${RED}FAIL${NC} - $RJ_LABEL must not consume key material"
    exit 1
  fi
  if ! grep -q "FAIL" mm_rj.err; then
    echo "     ! ${RED}FAIL${NC} - $RJ_LABEL must print FAIL to stderr"
    cat mm_rj.err
    exit 1
  fi
  for RJ_PAT in "$@"; do
    if ! grep -q "$RJ_PAT" mm_rj.err; then
      echo "     ! ${RED}FAIL${NC} - $RJ_LABEL stderr must name the reason: $RJ_PAT"
      cat mm_rj.err
      exit 1
    fi
  done
  echo "     - ${GREEN}PASS${NC} - $RJ_LABEL rejected with exit $RJ_EXPECT, no key consumed"
}

# expected next message here: seq 1, offset 0, source_id = key bytes 0-16
make_cipher_srcfile mm_deckey.txt 0 mm_badsrc.bin mm_probe.txt 1 0 mm_bad1.bin
reject_case 1 mm_bad1.bin "invalid source_id" "Invalid source_id"

make_cipher mm_deckey.txt 0 mm_probe.txt 9 0 mm_bad2.bin
reject_case 2 mm_bad2.bin "invalid seq" "Invalid seq"

make_cipher mm_deckey.txt 0 mm_probe.txt 1 500 mm_bad3.bin
reject_case 3 mm_bad3.bin "invalid offset" "Invalid offset"

make_cipher_srcfile mm_deckey.txt 0 mm_badsrc.bin mm_probe.txt 9 0 mm_bad4.bin
reject_case 4 mm_bad4.bin "invalid source_id and seq" "Invalid source_id" "Invalid seq"

make_cipher_srcfile mm_deckey.txt 0 mm_badsrc.bin mm_probe.txt 1 500 mm_bad7.bin
reject_case 7 mm_bad7.bin "invalid source_id and offset" "Invalid source_id" "Invalid offset"

make_cipher mm_deckey.txt 0 mm_probe.txt 9 500 mm_bad6.bin
reject_case 6 mm_bad6.bin "invalid seq and offset" "Invalid seq" "Invalid offset"

make_cipher_srcfile mm_deckey.txt 0 mm_badsrc.bin mm_probe.txt 9 500 mm_bad5.bin
reject_case 5 mm_bad5.bin "invalid source_id, seq and offset" "Invalid source_id" "Invalid seq" "Invalid offset"

# raw bytes with no metadata at all (e.g. pre-metadata or foreign
# ciphertext) decode to no parseable block: nothing is verifiable
printf 'this is not a valid otp message, just some bytes long enough' > mm_garbage.bin
reject_case 5 mm_garbage.bin "unparseable metadata" "no valid metadata"

# a truncated fragment of an otherwise valid message
make_cipher mm_deckey.txt 0 mm_probe.txt 1 0 mm_valid.bin
dd if=mm_valid.bin of=mm_short.bin bs=1 count=10 2>/dev/null
reject_case 5 mm_short.bin "truncated metadata" "no valid metadata"

# -----------------------------------------------------------------------------
#  after every rejection above, the expected valid message must still
#  decrypt: rejections really consumed nothing
# -----------------------------------------------------------------------------

echo "     Testing the channel survives every rejection untouched..."

./bin/otp -c mmrecv --decrypt < mm_valid.bin > mm_valid.out 2>mm_err.log
if [ $? -eq 0 ] && cmp -s mm_valid.out mm_probe.txt; then
  echo "     - ${GREEN}PASS${NC} - the valid message still decrypts after all rejections"
else
  echo "     ! ${RED}FAIL${NC} - rejections desynchronized the channel"
  cat mm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  a message whose metadata is valid but that carries no payload is an
#  error (the sender can never produce one), and consumes nothing
# -----------------------------------------------------------------------------

echo "     Testing a payload-less message is refused..."

rm -rf .keychain
dd if=/dev/urandom of=mm_key.txt bs=1 count=1000 2>/dev/null
dd if=/dev/urandom of=mm_deckey.txt bs=1 count=1000 2>/dev/null
./bin/otp --add-contact mmrecv mm_key.txt mm_deckey.txt > /dev/null 2>&1
cp .keychain/mmrecv_dec.key mm_deckey.snap

: > mm_empty.txt
make_cipher mm_deckey.txt 0 mm_empty.txt 1 0 mm_noload.bin
./bin/otp -c mmrecv --decrypt < mm_noload.bin > mm_noload.out 2>/dev/null
RC=$?
if [ $RC -eq 1 ] && [ ! -s mm_noload.out ] && cmp -s .keychain/mmrecv_dec.key mm_deckey.snap; then
  echo "     - ${GREEN}PASS${NC} - payload-less message refused (exit 1) with no key consumed"
else
  echo "     ! ${RED}FAIL${NC} - payload-less message handling wrong (exit $RC)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  dynamic-length seq/offset values
#
#  The length field is a ULEB128 varint, so a value may be of ANY
#  byte-length. A wide encoding of the CORRECT value (leading zeros, or
#  a length field spanning several varint bytes) must validate; a value
#  genuinely wider than this build's 64-bit counters is well-formed wire
#  that can never match, so it must fail seq/offset validation (its own
#  codes) - NOT be rejected as malformed.
# -----------------------------------------------------------------------------

echo "     Testing dynamic-length metadata values..."

rm -rf .keychain
dd if=/dev/urandom of=mm_key.txt bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=mm_deckey.txt bs=1 count=2000 2>/dev/null
./bin/otp --add-contact mmrecv mm_key.txt mm_deckey.txt > /dev/null 2>&1
printf 'wide encoding probe' > mm_probe.txt
cp .keychain/mmrecv_dec.key mm_deckey.snap

# seq 1 encoded in 10 bytes (9 leading zeros), offset 0 in 1 byte
{
  printf '\001'
  dd if=mm_deckey.txt bs=1 count=16 2>/dev/null
  printf '\002\012'
  dd if=/dev/zero bs=1 count=9 2>/dev/null
  printf '\001'
  printf '\003\001\000'
} > mm_widemeta.bin
make_cipher_from_meta mm_deckey.txt 0 mm_widemeta.bin mm_probe.txt mm_widec.bin
./bin/otp -c mmrecv --decrypt < mm_widec.bin > mm_wide.out 2>mm_err.log
RC=$?
if [ $RC -eq 0 ] && cmp -s mm_wide.out mm_probe.txt; then
  echo "     - ${GREEN}PASS${NC} - a 10-byte encoding of the correct seq validates and decrypts"
else
  echo "     ! ${RED}FAIL${NC} - wide encoding of a correct value was rejected (exit $RC)"
  cat mm_err.log
  exit 1
fi

# message #2: seq 2 in a 200-byte value, whose length (200) itself needs
# a two-byte varint (0xC8 0x01); offset encoded with 3 leading zeros
WIDE1_META=$(wc -c < mm_widemeta.bin | tr -d ' ')
WIDE1_PLEN=$(wc -c < mm_probe.txt | tr -d ' ')
OFF2=$((16 + WIDE1_META + WIDE1_PLEN))
{
  printf '\001'
  dd if=mm_deckey.txt bs=1 skip="$OFF2" count=16 2>/dev/null
  printf '\002\310\001'
  dd if=/dev/zero bs=1 count=199 2>/dev/null
  printf '\002'
  printf '\003\004'
  dd if=/dev/zero bs=1 count=3 2>/dev/null
  printf "$(meta_uint_esc "$OFF2")"
} > mm_widemeta2.bin
printf 'second wide message' > mm_probe2.txt
make_cipher_from_meta mm_deckey.txt "$OFF2" mm_widemeta2.bin mm_probe2.txt mm_widec2.bin
./bin/otp -c mmrecv --decrypt < mm_widec2.bin > mm_wide2.out 2>mm_err.log
RC=$?
if [ $RC -eq 0 ] && cmp -s mm_wide2.out mm_probe2.txt; then
  echo "     - ${GREEN}PASS${NC} - a 200-byte value behind a two-byte varint length validates and decrypts"
else
  echo "     ! ${RED}FAIL${NC} - multi-byte varint length was rejected (exit $RC)"
  cat mm_err.log
  exit 1
fi

# message #3 slot: seq of 26 non-zero bytes (~10^62) and offset of 43
# non-zero bytes (~10^103) - astronomically beyond any real key. Both
# can never match, so: exit 6 (invalid seq and offset), source_id fine,
# nothing consumed, and the reasons name the out-of-range values.
WIDE2_META=$(wc -c < mm_widemeta2.bin | tr -d ' ')
WIDE2_PLEN=$(wc -c < mm_probe2.txt | tr -d ' ')
OFF3=$((OFF2 + 16 + WIDE2_META + WIDE2_PLEN))
cp .keychain/mmrecv_dec.key mm_deckey.snap
{
  printf '\001'
  dd if=mm_deckey.txt bs=1 skip="$OFF3" count=16 2>/dev/null
  printf '\002\032'
  i=0; while [ $i -lt 26 ]; do printf '\377'; i=$((i+1)); done
  printf '\003\053'
  i=0; while [ $i -lt 43 ]; do printf '\377'; i=$((i+1)); done
} > mm_hugemeta.bin
make_cipher_from_meta mm_deckey.txt "$OFF3" mm_hugemeta.bin mm_probe.txt mm_hugec.bin
./bin/otp -c mmrecv --decrypt < mm_hugec.bin > mm_huge.out 2>mm_err.log
RC=$?
if [ $RC -eq 6 ] && [ ! -s mm_huge.out ] && cmp -s .keychain/mmrecv_dec.key mm_deckey.snap &&
   grep -q "too large for this build" mm_err.log; then
  echo "     - ${GREEN}PASS${NC} - astronomically wide seq/offset fail their own validation (exit 6), not as malformed"
else
  echo "     ! ${RED}FAIL${NC} - out-of-range wide values mishandled (exit $RC, expected 6)"
  cat mm_err.log
  exit 1
fi

# -----------------------------------------------------------------------------
#  full binary-to-binary roundtrip between two mirrored keychains, three
#  messages deep, to prove sender and receiver stay in lockstep
# -----------------------------------------------------------------------------

echo "     Testing a three-message roundtrip stays in lockstep..."

rm -rf .keychain mm_alice mm_bob
mkdir mm_alice mm_bob
dd if=/dev/urandom of=mm_ab.key bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=mm_ba.key bs=1 count=2000 2>/dev/null
OTP_BIN="$(pwd)/bin/otp"
cp mm_ab.key mm_alice/ab.key; cp mm_ba.key mm_alice/ba.key
cp mm_ab.key mm_bob/ab.key;   cp mm_ba.key mm_bob/ba.key
(cd mm_alice && "$OTP_BIN" --add-contact bob ab.key ba.key > /dev/null 2>&1)
(cd mm_bob && "$OTP_BIN" --add-contact alice ba.key ab.key > /dev/null 2>&1)

ROUND_OK=1
for i in 1 2 3; do
  printf 'roundtrip message number %s' "$i" > mm_round_in.txt
  (cd mm_alice && "$OTP_BIN" -c bob --encrypt < ../mm_round_in.txt > ../mm_round_c.bin 2>/dev/null) || ROUND_OK=0
  (cd mm_bob && "$OTP_BIN" -c alice --decrypt < ../mm_round_c.bin > ../mm_round_out.txt 2>/dev/null) || ROUND_OK=0
  cmp -s mm_round_in.txt mm_round_out.txt || ROUND_OK=0
done

if [ $ROUND_OK -eq 1 ]; then
  echo "     - ${GREEN}PASS${NC} - three consecutive messages round-tripped exactly"
else
  echo "     ! ${RED}FAIL${NC} - the mirrored keychains fell out of lockstep"
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf .keychain mm_alice mm_bob
rm -f mm_*

echo ""
exit 0
