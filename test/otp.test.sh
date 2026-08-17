#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# plain:              16ag
# key:                abcdefghijklmn  (first 4 bytes in ./test_data/test.txt file)
# expected cipher:    PT
# expected next key:  efghijklmn      (last 4 bytes in ./test_data/test.txt file)
export PLAIN='16ag'
export COMPUTED_CIPHER=`printf '%s' $PLAIN | ./bin/otp ./test/test_data/test.txt`
export EXPECTED_CIPHER=$(printf 'PT\x02\x03')
export EXPECTED_NEXT_KEY="efghijklmn"
export NOW=`date +"%Y-%m-%d_%H-%M-%S"`

# -----------------------------------------------------------------------------
#  test encryption / decryption
# -----------------------------------------------------------------------------

echo ""
echo "   - Encryption / Decryption algorythm"

if [ "$COMPUTED_CIPHER" = "$EXPECTED_CIPHER" ]; then
  echo "     - ${GREEN}PASS${NC} - output is correct"
else
  echo "     ! ${RED}FAIL${NC} - Expected $EXPECTED_CIPHER but got $COMPUTED_CIPHER"
  exit 1
fi

if test -f "./test/test_data/test.txt.$NOW.next"; then
  echo "     - ${GREEN}PASS${NC} - next key file was created"
else
  echo "     - ${RED}FAIL${NC} - next key file was NOT created!"
  exit 1
fi

export NEXT_KEY=`cat ./test/test_data/test.txt.$NOW.next`
if [ "$NEXT_KEY" = "$EXPECTED_NEXT_KEY" ]; then
  echo "     - ${GREEN}PASS${NC} - next key file has correct key (content)"
else
  echo "     ! ${RED}FAIL${NC} - next key file has WRONG key (content), expected '$EXPECTED_NEXT_KEY' but got '$NEXT_KEY'"
  exit 1
fi

rm ./test/test_data/test.txt.$NOW.next

export COMPUTED_PLAN_FROM_CIPHER=`printf '%s' $COMPUTED_CIPHER | ./bin/otp ./test/test_data/test.txt`
if [ "$COMPUTED_PLAN_FROM_CIPHER" = "$PLAIN" ]; then
  echo "     - ${GREEN}PASS${NC} - decryption (content) is correct"
else
  echo "     ! ${RED}FAIL${NC} - decryption (content) is incorrect, expected '$PLAIN' but got '$COMPUTED_PLAN_FROM_CIPHER'"
  exit 1
fi

# the decryption run above writes its own timestamped .next file - remove it
rm -f ./test/test_data/test.txt.*.next

# -----------------------------------------------------------------------------
#  test key pair generation
# -----------------------------------------------------------------------------
echo ""
echo "   - Key generation"

export KEY_SIZE_MB=1
export PARTA=parta
export PARTB=partb

# Generate key pair using test data as stdin (leftover directories from an
# aborted earlier run would make the O_EXCL file creation fail)
rm -rf ${PARTA}_keys ${PARTB}_keys
dd if=/dev/urandom of=tmpkey bs=1M count=2 2>/dev/null
GEN_OUT=$(cat tmpkey | ./bin/otp --new-key-pair $KEY_SIZE_MB $PARTA $PARTB)
rm tmpkey

# Verify the progress/report output around mid-interruption awareness:
# the run must announce itself, end with the OK the announcement promises,
# list the generated layout with sizes, and remind the user to store the
# keys safely. stdout here is captured (not a terminal), so the output
# must also be plain text - no ANSI color codes and no spinner.
if printf '%s' "$GEN_OUT" | grep -q "Generating key pair of ${KEY_SIZE_MB} MB"; then
  echo "     - ${GREEN}PASS${NC} - generation announces itself with the key size"
else
  echo "     ! ${RED}FAIL${NC} - missing 'Generating key pair of ${KEY_SIZE_MB} MB' in output: $GEN_OUT"
  exit 1
fi
if printf '%s' "$GEN_OUT" | grep -q "^OK$"; then
  echo "     - ${GREEN}PASS${NC} - completed generation reports OK on its own line"
else
  echo "     ! ${RED}FAIL${NC} - missing standalone OK line in generation output: $GEN_OUT"
  exit 1
fi
if printf '%s' "$GEN_OUT" | grep -q "${PARTA}_keys/" &&
   printf '%s' "$GEN_OUT" | grep -q "encryption_for_${PARTB}.key ($((KEY_SIZE_MB*1024*1024)) bytes)" &&
   printf '%s' "$GEN_OUT" | grep -q "decryption_from_${PARTA}.key ($((KEY_SIZE_MB*1024*1024)) bytes)"; then
  echo "     - ${GREEN}PASS${NC} - report lists the generated directories and key sizes"
else
  echo "     ! ${RED}FAIL${NC} - generated layout/sizes missing from output: $GEN_OUT"
  exit 1
fi
if printf '%s' "$GEN_OUT" | grep -q "Store/Share the keys safely!"; then
  echo "     - ${GREEN}PASS${NC} - reminds the user to store/share the keys safely"
else
  echo "     ! ${RED}FAIL${NC} - missing 'Store/Share the keys safely!' in output: $GEN_OUT"
  exit 1
fi
if printf '%s' "$GEN_OUT" | grep -q $'\x1b'; then
  echo "     ! ${RED}FAIL${NC} - ANSI escape codes leaked into non-terminal output"
  exit 1
else
  echo "     - ${GREEN}PASS${NC} - output is plain text when stdout is not a terminal"
fi

# Verify files exist (each party's pair lives in its own <name>_keys/ directory,
# each file named for the correspondent it is used with)
for f in ${PARTA}_keys/encryption_for_${PARTB}.key ${PARTA}_keys/decryption_from_${PARTB}.key ${PARTB}_keys/encryption_for_${PARTA}.key ${PARTB}_keys/decryption_from_${PARTA}.key; do
  if [ ! -f "${f}" ]; then
    echo "     ! ${RED}FAIL${NC} - expected key file ${f} not found"
    exit 1
  fi
  # Verify size
  sz=$(wc -c < "${f}" 2>/dev/null | tr -d ' ')
  if [ "$sz" -ne $((KEY_SIZE_MB*1024*1024)) ]; then
    echo "     ! ${RED}FAIL${NC} - key file ${f} size $sz does not match expected $((KEY_SIZE_MB*1024*1024))"
    exit 1
  fi
  echo "     - ${GREEN}PASS${NC} - ${f} exists and correct size"
done

# Verify cross assignment
encryption_a=$(cat ${PARTA}_keys/encryption_for_${PARTB}.key | base64 | tr -d '\n')
decryption_a=$(cat ${PARTA}_keys/decryption_from_${PARTB}.key | base64 | tr -d '\n')
encryption_b=$(cat ${PARTB}_keys/encryption_for_${PARTA}.key | base64 | tr -d '\n')
decryption_b=$(cat ${PARTB}_keys/decryption_from_${PARTA}.key | base64 | tr -d '\n')

if [ "$encryption_a" != "$decryption_b" ]; then
  echo "     ! ${RED}FAIL${NC} - ${PARTA}_keys/encryption_for_${PARTB}.key does not match ${PARTB}_keys/decryption_from_${PARTA}.key"
  exit 1
fi
if [ "$decryption_a" != "$encryption_b" ]; then
  echo "     ! ${RED}FAIL${NC} - ${PARTA}_keys/decryption_from_${PARTB}.key does not match ${PARTB}_keys/encryption_for_${PARTA}.key"
  exit 1
fi
echo "     - ${GREEN}PASS${NC} - key pair is symetric"
echo ""

# -----------------------------------------------------------------------------
#  test key pair generation refuses a terminal stdin
# -----------------------------------------------------------------------------
# Run --new-key-pair with stdin attached to a pseudo-terminal (via script(1))
# instead of a pipe: it must refuse immediately - before creating any
# directory or file - rather than block waiting for typed key material.
# script's own stdin is /dev/null so that even a regression (no refusal)
# ends with a read error instead of hanging the test suite.
echo "   - Key generation with terminal stdin"

rm -rf ttya_keys ttyb_keys
TTY_TESTED=""
if script --version 2>/dev/null | grep -q util-linux; then
  # util-linux script (Linux): -c runs the command, -e keeps its exit code
  TTY_OUT=$(script -qec "./bin/otp --new-key-pair 1 ttya ttyb" /dev/null < /dev/null 2>&1)
  TTY_TESTED=1
elif [ "$(uname)" = "Darwin" ]; then
  # BSD script (macOS): command given directly after the typescript file
  TTY_OUT=$(script -q /dev/null ./bin/otp --new-key-pair 1 ttya ttyb < /dev/null 2>&1)
  TTY_TESTED=1
fi

if [ -z "$TTY_TESTED" ]; then
  echo "     - SKIP - no way to allocate a pseudo-terminal on this platform"
else
  if printf '%s' "$TTY_OUT" | grep -q "stdin is a terminal"; then
    echo "     - ${GREEN}PASS${NC} - expected to read random key from pipe but no pipe was provided"
  else
    echo "     ! ${RED}FAIL${NC} - expected a refusal when stdin is a terminal, got: $TTY_OUT"
    exit 1
  fi
  if [ ! -e ttya_keys ] && [ ! -e ttyb_keys ]; then
    echo "     - ${GREEN}PASS${NC} - refused run created no directory or file"
  else
    echo "     ! ${RED}FAIL${NC} - refused run left ttya_keys/ or ttyb_keys/ behind"
    rm -rf ttya_keys ttyb_keys
    exit 1
  fi
fi
echo ""

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf ${PARTA}_keys ${PARTB}_keys
exit 0
