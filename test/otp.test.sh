#!/bin/sh

# plain:              16ag
# key:                abcdefghijklmn  (first 4 bytes in ./test_data/test.txt file)
# expected cipher:    PT
# expected next key:  efghijklmn      (last 4 bytes in ./test_data/test.txt file)
export PLAIN='16ag'
export COMPUTED_CIPHER=`printf '%s' $PLAIN | ./bin/otp ./test/test_data/test.txt`
export EXPECTED_CIPHER=$'PT\x02\x03'
export EXPECTED_NEXT_KEY="efghijklmn"
export NOW=`date +"%Y-%m-%d_%H-%M-%S"`

# -----------------------------------------------------------------------------
#  test encryption / decryption
# -----------------------------------------------------------------------------

echo ""
echo "   - Encryption / Decryption algorythm"

if [ "$COMPUTED_CIPHER" = "$EXPECTED_CIPHER" ]; then
  echo "     - PASS - output is correct"
else
  echo "     ! FAIL - Expected $EXPECTED_CIPHER but got $COMPUTED_CIPHER"
  exit -1
fi

if test -f "./test/test_data/test.txt.$NOW.next"; then
  echo "     - PASS - next key file was created"
else
  echo "     - FAIL - next key file was NOT created!"
  exit -1
fi

export NEXT_KEY=`cat ./test/test_data/test.txt.$NOW.next`
if [ "$NEXT_KEY" = "$EXPECTED_NEXT_KEY" ]; then
  echo "     - PASS - next key file has correct key (content)"
else
  echo "     ! FAIL - next key file has WRONG key (content), expected '$EXPECTED_NEXT_KEY' but got '$NEXT_KEY'"
  exit -1
fi

rm ./test/test_data/test.txt.$NOW.next

export COMPUTED_PLAN_FROM_CIPHER=`printf '%s' $COMPUTED_CIPHER | ./bin/otp ./test/test_data/test.txt`
if [[ "$COMPUTED_PLAN_FROM_CIPHER" = "$PLAIN" ]]; then
  echo "     - PASS - decryption (content) is correct"
else
  echo "     ! FAIL - decryption (content) is incorrect, expected '$PLAIN' but got '$COMPUTED_PLAN_FROM_CIPHER'"
  exit -1
fi

# -----------------------------------------------------------------------------
#  test key pair generation
# -----------------------------------------------------------------------------
echo ""
echo "   - Key generation"

export KEY_SIZE_MB=1
export PARTA=parta
export PARTB=partb

# Generate key pair using test data as stdin
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
cat tmpkey | ./bin/otp --new-key-pair $KEY_SIZE_MB $PARTA $PARTB
rm tmpkey

# Verify files exist
for f in encryption_${PARTA}.txt decryption_${PARTA}.txt encryption_${PARTB}.txt decryption_${PARTB}.txt; do
  if [ ! -f "${f}" ]; then
    echo "     ! FAIL - expected key file ${f} not found"
    exit -1
  fi
  # Verify size
  sz=$(wc -c < "${f}" 2>/dev/null)
  if [ "$sz" -ne $((KEY_SIZE_MB*1024*1024)) ]; then
    echo "     ! FAIL - key file ${f} size $sz does not match expected $((KEY_SIZE_MB*1024*1024))"
    exit -1
  fi
  echo "     - PASS - ${f} exists and correct size"
done

# Verify cross assignment
encryption_a=$(cat encryption_${PARTA}.txt | base64 | tr -d '\n')
decryption_a=$(cat decryption_${PARTA}.txt | base64 | tr -d '\n')
encryption_b=$(cat encryption_${PARTB}.txt | base64 | tr -d '\n')
decryption_b=$(cat decryption_${PARTB}.txt | base64 | tr -d '\n')

if [ "$encryption_a" != "$decryption_b" ]; then
  echo "     ! FAIL - encryption_${PARTA} does not match decryption_${PARTB}"
  exit -1
fi
if [ "$decryption_a" != "$encryption_b" ]; then
  echo "     ! FAIL - decryption_${PARTA} does not match encryption_${PARTB}"
  exit -1
fi
echo "     - PASS - key pair is symetric"
echo ""

rm encryption_${PARTA}.txt decryption_${PARTA}.txt encryption_${PARTB}.txt decryption_${PARTB}.txt
exit 0
