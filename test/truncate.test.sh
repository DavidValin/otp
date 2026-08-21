#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# These tests exercise key truncation, not the delivery-confirmation gate
# (see test/confirm.test.sh for that), so state the confirmation explicitly.
OTP_ASSUME_DELIVERED=1
export OTP_ASSUME_DELIVERED

# Regression test: a message that consumes exactly all remaining key must
# leave the key file truncated to 0 bytes on disk. The spent key bytes are
# the secret that protected an already-sent message; leaving them behind
# (e.g. by treating a NULL return from malloc(0) as an allocation failure
# and skipping the truncation - the C standard permits malloc(0) to return
# NULL) would keep recoverable pad material on disk and invite reuse.
#
# Scenario 1 checks the invariant under the platform's real malloc.
# Scenario 2 repeats it with an LD_PRELOAD shim that forces malloc(0) to
# return NULL, so the zero-remaining path is exercised the way a
# standard-conforming-but-unusual allocator would behave, even on glibc.

echo ""
echo "   - Full-key-consumption truncation"

KEY_BYTES=1048576  # --new-key-pair 1 creates 1MB keys per direction

# A message additionally consumes the 16-byte source_id chunk plus the
# metadata pad, so full consumption means a payload smaller by exactly
# that overhead (39 bytes for a first message: seq 1 and offset 0).
. test/xor.helper.sh
MSG_BYTES=$((KEY_BYTES - $(meta_consumed_len 0 1 0)))

# run_full_consumption <contact-name>
# Fresh keychain, 1MB keys, then encrypt a message of exactly KEY_BYTES.
# Asserts: encrypt succeeds, key file is 0 bytes, metadata says 0 bytes,
# and no stale .keychain/<name>_enc.key.tmp is left behind.
run_full_consumption() {
  NAME=$1

  rm -rf .keychain "${NAME}_keys" "${NAME}peer_keys"
  dd if=/dev/urandom of=trunc_tmpkey bs=1048576 count=2 2>/dev/null
  cat trunc_tmpkey | ./bin/otp --new-key-pair 1 "$NAME" "${NAME}peer" > /dev/null 2>&1
  rm -f trunc_tmpkey
  ./bin/otp --add-contact "$NAME" "${NAME}_keys/encryption_for_${NAME}peer.key" "${NAME}_keys/decryption_from_${NAME}peer.key" > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo "     ! ${RED}FAIL${NC} - test setup: could not create contact $NAME with keys"
    exit 1
  fi

  dd if=/dev/zero of=trunc_full_msg.bin bs=$MSG_BYTES count=1 2>/dev/null
  ./bin/otp -c "$NAME" --encrypt < trunc_full_msg.bin > trunc_cipher.bin 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - message consuming exactly all remaining key encrypts successfully"
  else
    echo "     ! ${RED}FAIL${NC} - encrypting a message of exactly the remaining key size failed"
    exit 1
  fi

  if [ ! -f ".keychain/${NAME}_enc.key" ]; then
    echo "     ! ${RED}FAIL${NC} - key file .keychain/${NAME}_enc.key disappeared instead of being truncated"
    exit 1
  fi

  KEY_LEFT=$(wc -c < ".keychain/${NAME}_enc.key" | tr -d ' ')
  if [ "$KEY_LEFT" = "0" ]; then
    echo "     - ${GREEN}PASS${NC} - fully-consumed key file was truncated to 0 bytes"
  else
    echo "     ! ${RED}FAIL${NC} - fully-consumed key file still holds $KEY_LEFT bytes of spent pad material"
    exit 1
  fi

  OUTPUT=$(./bin/otp --show-contact "$NAME")
  echo "$OUTPUT" | grep -q "EncryptionKey: \*\*\*\*\*\*\* (0 bytes)"
  if [ $? -eq 0 ]; then
    echo "     - ${GREEN}PASS${NC} - metadata agrees the encryption key is exhausted (0 bytes)"
  else
    echo "     ! ${RED}FAIL${NC} - metadata does not report 0 remaining encryption key bytes"
    exit 1
  fi

  if [ ! -f ".keychain/${NAME}_enc.key.tmp" ]; then
    echo "     - ${GREEN}PASS${NC} - no stale key staging file left behind"
  else
    echo "     ! ${RED}FAIL${NC} - stale staging file .keychain/${NAME}_enc.key.tmp left behind"
    exit 1
  fi

  rm -f trunc_full_msg.bin trunc_cipher.bin
  rm -rf "${NAME}_keys" "${NAME}peer_keys"
}

# -----------------------------------------------------------------------------
#  scenario 1: full consumption under the real allocator
# -----------------------------------------------------------------------------

echo "     Testing exact full key consumption..."
run_full_consumption trunc0

# -----------------------------------------------------------------------------
#  scenario 2: same, with malloc(0) forced to return NULL
# -----------------------------------------------------------------------------

echo "     Testing exact full key consumption with malloc(0) == NULL..."

SHIM_OK=0
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && command -v cc > /dev/null 2>&1; then
  cat > trunc_malloc0_shim.c <<'EOF'
#include <stddef.h>
/* glibc's real allocator, reachable without dlsym (which itself mallocs) */
extern void *__libc_malloc(size_t size);
void *malloc(size_t size)
{
  if (size == 0)
    return NULL;
  return __libc_malloc(size);
}
EOF
  cat > trunc_malloc0_check.c <<'EOF'
#include <stdlib.h>
int main(void) { return malloc(0) == NULL ? 0 : 1; }
EOF
  if cc -shared -fPIC -o trunc_malloc0_shim.so trunc_malloc0_shim.c 2>/dev/null &&
     cc -o trunc_malloc0_check trunc_malloc0_check.c 2>/dev/null &&
     LD_PRELOAD="$(pwd)/trunc_malloc0_shim.so" ./trunc_malloc0_check; then
    SHIM_OK=1
  fi
fi

if [ "$SHIM_OK" = "1" ]; then
  LD_PRELOAD="$(pwd)/trunc_malloc0_shim.so"
  export LD_PRELOAD
  run_full_consumption trunc1
  unset LD_PRELOAD
else
  echo "     - SKIP - cannot build/verify a malloc(0)==NULL preload shim on this platform"
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain
rm -rf trunc_* trunc*_keys
