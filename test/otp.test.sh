#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

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
dd if=/dev/urandom of=tmpkey bs=1048576 count=2 2>/dev/null
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
if printf '%s' "$GEN_OUT" | grep -q "$(printf '\033')"; then
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

# Verify cross assignment (raw byte comparison - no need to encode)
if ! cmp -s ${PARTA}_keys/encryption_for_${PARTB}.key ${PARTB}_keys/decryption_from_${PARTA}.key; then
  echo "     ! ${RED}FAIL${NC} - ${PARTA}_keys/encryption_for_${PARTB}.key does not match ${PARTB}_keys/decryption_from_${PARTA}.key"
  exit 1
fi
if ! cmp -s ${PARTA}_keys/decryption_from_${PARTB}.key ${PARTB}_keys/encryption_for_${PARTA}.key; then
  echo "     ! ${RED}FAIL${NC} - ${PARTA}_keys/decryption_from_${PARTB}.key does not match ${PARTB}_keys/encryption_for_${PARTA}.key"
  exit 1
fi
echo "     - ${GREEN}PASS${NC} - key pair is symetric"
echo ""

# -----------------------------------------------------------------------------
#  test key pair generation refuses a terminal stdin when no randomness
#  vault is available to fall back to
# -----------------------------------------------------------------------------
# Run --new-key-pair with stdin attached to a pseudo-terminal (via script(1))
# instead of a pipe: with no .keychain/_randomness vault around to offer
# instead, it must refuse immediately - before creating any directory or
# file - rather than block waiting for typed key material. (Falling back to
# a sufficiently large vault instead of refusing is covered separately in
# randvault.test.sh.) script's own stdin is /dev/null so that even a
# regression (no refusal) ends with a read error instead of hanging the
# test suite.
echo "   - Key generation with terminal stdin"

rm -rf ttya_keys ttyb_keys .keychain
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
  if printf '%s' "$TTY_OUT" | grep -q "no randomness vault"; then
    echo "     - ${GREEN}PASS${NC} - expected to read random key from pipe but no pipe (or vault) was provided"
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
#  the removed direct key-file mode must be rejected, not silently accepted
# -----------------------------------------------------------------------------
# `otp <keyfile>` used to encrypt stdin against a bare key file. That mode
# is gone; a leftover script still invoking it must get an error and no
# output, never ciphertext produced outside the keychain's key accounting.
echo "   - Direct key-file invocation is rejected"

printf 'somekeymaterial' > direct_mode_key.tmp
DIRECT_OUT=$(printf 'plain' | ./bin/otp direct_mode_key.tmp 2>direct_mode_err.tmp)
DIRECT_RC=$?
if [ $DIRECT_RC -ne 0 ] && [ -z "$DIRECT_OUT" ] && grep -q "Unknown command" direct_mode_err.tmp; then
  echo "     - ${GREEN}PASS${NC} - a bare key-file argument fails with an unknown-command error"
else
  echo "     ! ${RED}FAIL${NC} - expected a rejection (got exit $DIRECT_RC, stdout '$DIRECT_OUT')"
  rm -f direct_mode_key.tmp direct_mode_err.tmp direct_mode_key.tmp.*.next
  exit 1
fi
if ls direct_mode_key.tmp.*.next > /dev/null 2>&1; then
  echo "     ! ${RED}FAIL${NC} - the rejected invocation still produced a .next file"
  rm -f direct_mode_key.tmp direct_mode_err.tmp direct_mode_key.tmp.*.next
  exit 1
else
  echo "     - ${GREEN}PASS${NC} - no .next successor file was created"
fi
rm -f direct_mode_key.tmp direct_mode_err.tmp
echo ""

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."

rm -rf ${PARTA}_keys ${PARTB}_keys
exit 0
