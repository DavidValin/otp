#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --new-key-pair sourced from the randomness vault instead of a pipe.
#
# With stdin on a terminal (no pipe), --new-key-pair now offers to draw its
# randomness from .keychain/_randomness (filled by --add-rand-to-vault)
# instead of refusing outright - but only when the vault holds enough:
# generating a pair of <size_in_MB> needs two independent pads of that size
# (see the "two random keys, four files" split in README.md), so 2x
# <size_in_MB> bytes must be available. All of this only ever triggers with
# no pipe; the piped path (tested in otp.test.sh) is unchanged.
#
# These tests drive the terminal prompt through a real pseudo-terminal via
# script(1), the same technique otp.test.sh and confirm.test.sh already use
# for terminal-only behavior - there is no test-only env-var bypass for
# this prompt.

rm -rf .keychain vka_keys vkb_keys vka2_keys vkb2_keys
rm -f vk_*

echo ""
echo "   - --new-key-pair sourced from the randomness vault"

TTY_TESTED=""
run_pty() {
  # run_pty <answer-or-empty> <otp-args...> ; sets TTY_OUT, TTY_RC
  ans=$1; shift
  if script --version 2>/dev/null | grep -q util-linux; then
    if [ -n "$ans" ]; then
      TTY_OUT=$(printf '%s\n' "$ans" | script -qec "./bin/otp $*" vk_tty.log 2>&1)
    else
      TTY_OUT=$(script -qec "./bin/otp $*" vk_tty.log < /dev/null 2>&1)
    fi
    TTY_RC=$?
    TTY_TESTED=1
  elif [ "$(uname)" = "Darwin" ]; then
    if [ -n "$ans" ]; then
      # BSD script(1) relays stdin to the child's pty; if the feeder pipe
      # closes (EOF) the instant the answer is written, a child that isn't
      # at its read() yet (still loading the keychain, checking the vault
      # size, etc.) can race that EOF instead of the answer that was
      # already sent. Holding the pipe open briefly after the write gives
      # the child time to reach fgets() first.
      TTY_OUT=$( { printf '%s\n' "$ans"; sleep 0.3; } | script -q vk_tty.log sh -c "./bin/otp $*" 2>&1)
    else
      TTY_OUT=$(script -q /dev/null ./bin/otp $* < /dev/null 2>&1)
    fi
    TTY_RC=$?
    TTY_TESTED=1
  fi
  rm -f vk_tty.log
}

# -----------------------------------------------------------------------------
#  no vault at all: falls back to the stdin-refusal message
# -----------------------------------------------------------------------------

echo "     Testing no vault falls back with the stdin-pipe message..."

run_pty "" --new-key-pair 2 vka vkb
if [ -z "$TTY_TESTED" ]; then
  echo "     - SKIP - no way to allocate a pseudo-terminal on this platform"
else
  if printf '%s' "$TTY_OUT" | grep -q "no randomness vault size above 1 bit" &&
     printf '%s' "$TTY_OUT" | grep -q "please provide randomness via stdin"; then
    echo "     - ${GREEN}PASS${NC} - refused with the no-vault fallback message"
  else
    echo "     ! ${RED}FAIL${NC} - expected the no-vault fallback message, got: $TTY_OUT"
    exit 1
  fi
  if [ ! -e vka_keys ] && [ ! -e vkb_keys ]; then
    echo "     - ${GREEN}PASS${NC} - no directory or file created"
  else
    echo "     ! ${RED}FAIL${NC} - refused run left vka_keys/ or vkb_keys/ behind"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
#  vault present but smaller than the 2x<size_in_MB> a pair needs: same
#  fallback, vault left untouched
# -----------------------------------------------------------------------------

echo "     Testing an insufficient vault also falls back..."

dd if=/dev/urandom of=vk_src.tmp bs=1048576 count=2 2>/dev/null
cat vk_src.tmp | ./bin/otp --add-rand-to-vault 2 > /dev/null 2>&1

run_pty "" --new-key-pair 2 vka vkb
if [ -n "$TTY_TESTED" ]; then
  if printf '%s' "$TTY_OUT" | grep -q "no randomness vault size above 1 bit"; then
    echo "     - ${GREEN}PASS${NC} - a too-small vault (2 MB, needs 4 MB) also falls back"
  else
    echo "     ! ${RED}FAIL${NC} - expected the no-vault fallback message, got: $TTY_OUT"
    exit 1
  fi
  if [ "$(wc -c < .keychain/_randomness | tr -d ' ')" = "2097152" ]; then
    echo "     - ${GREEN}PASS${NC} - vault left untouched"
  else
    echo "     ! ${RED}FAIL${NC} - vault size changed after a refused run"
    exit 1
  fi
fi

# top up the vault to exactly the 4 MB a size-2 pair needs (2 independent
# 2 MB pads)
cat vk_src.tmp | ./bin/otp --add-rand-to-vault 2 > /dev/null 2>&1
cp .keychain/_randomness vk_vault_full.bin

# -----------------------------------------------------------------------------
#  answering 'n' cancels: no keys created, vault untouched
# -----------------------------------------------------------------------------

echo "     Testing 'n' cancels, vault left untouched..."

run_pty n --new-key-pair 2 vka vkb
if [ -n "$TTY_TESTED" ]; then
  if printf '%s' "$TTY_OUT" | grep -q "Use randomness vault for key generation?" &&
     printf '%s' "$TTY_OUT" | grep -q "Operation canceled"; then
    echo "     - ${GREEN}PASS${NC} - prompted, then cancelled on 'n'"
  else
    echo "     ! ${RED}FAIL${NC} - expected the prompt then Operation canceled, got: $TTY_OUT"
    exit 1
  fi
  if [ ! -e vka_keys ] && [ ! -e vkb_keys ] && cmp -s .keychain/_randomness vk_vault_full.bin; then
    echo "     - ${GREEN}PASS${NC} - no keys created, vault byte-identical to before the prompt"
  else
    echo "     ! ${RED}FAIL${NC} - cancel must not touch the vault or create key files"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
#  answering 'y' generates the pair from the vault, exactly like a piped
#  generation would from the same bytes, and the vault is fully consumed
# -----------------------------------------------------------------------------

echo "     Testing 'y' generates the pair from the vault..."

run_pty y --new-key-pair 2 vka vkb
if [ -n "$TTY_TESTED" ]; then
  if [ "$TTY_RC" = "0" ] && printf '%s' "$TTY_OUT" | grep -q "OK"; then
    echo "     - ${GREEN}PASS${NC} - generation succeeded"
  else
    echo "     ! ${RED}FAIL${NC} - vault-sourced generation should succeed, got (rc=$TTY_RC): $TTY_OUT"
    exit 1
  fi

  dd if=vk_vault_full.bin of=vk_pad1.bin bs=1048576 count=2 2>/dev/null
  dd if=vk_vault_full.bin of=vk_pad2.bin bs=1048576 skip=2 count=2 2>/dev/null

  if cmp -s vka_keys/encryption_for_vkb.key vk_pad1.bin &&
     cmp -s vkb_keys/decryption_from_vka.key vk_pad1.bin &&
     cmp -s vka_keys/decryption_from_vkb.key vk_pad2.bin &&
     cmp -s vkb_keys/encryption_for_vka.key vk_pad2.bin; then
    echo "     - ${GREEN}PASS${NC} - generated keys are exactly the vault's two claimed pads"
  else
    echo "     ! ${RED}FAIL${NC} - generated key files do not match the vault content that was claimed"
    exit 1
  fi

  if [ -f .keychain/_randomness ] && [ "$(wc -c < .keychain/_randomness | tr -d ' ')" = "0" ]; then
    echo "     - ${GREEN}PASS${NC} - vault fully consumed (4 MB claimed, 4 MB was available)"
  else
    echo "     ! ${RED}FAIL${NC} - vault should be drained to 0 bytes"
    exit 1
  fi

  PENDING_LEFT=$(ls .keychain/_randomness_pending_* 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PENDING_LEFT" = "0" ]; then
    echo "     - ${GREEN}PASS${NC} - no leftover pending vault claim after a full success"
  else
    echo "     ! ${RED}FAIL${NC} - a pending vault claim artifact was left behind"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
#  crash recovery: a run that crashes after the claim is durably staged but
#  before the vault is truncated must be resumable by a later run with the
#  same size and party names, without drawing fresh (and therefore
#  double-spent) randomness from the vault
# -----------------------------------------------------------------------------

echo "     Testing crash recovery of an interrupted vault claim..."

rm -rf vka2_keys vkb2_keys
rm -rf .keychain
# 6 MB in the vault for a size-2 pair (needs 4 MB): the truncate step must
# still have a non-empty tail (2 MB) to copy, which is what puts the
# during_key_truncate crash point on the code path actually taken - a vault
# claimed down to exactly 0 bytes remaining never enters that copy loop.
dd if=/dev/urandom of=vk_src2.tmp bs=1048576 count=2 2>/dev/null
cat vk_src2.tmp | ./bin/otp --add-rand-to-vault 2 > /dev/null 2>&1
cat vk_src2.tmp | ./bin/otp --add-rand-to-vault 2 > /dev/null 2>&1
dd if=/dev/urandom of=vk_src2_extra.tmp bs=1048576 count=2 2>/dev/null
cat vk_src2_extra.tmp | ./bin/otp --add-rand-to-vault 2 > /dev/null 2>&1
cp .keychain/_randomness vk_vault_full2.bin

if script --version 2>/dev/null | grep -q util-linux; then
  CRASH_OUT=$(printf 'y\n' | OTP_TEST_CRASH_POINT=during_key_truncate script -qec "./bin/otp --new-key-pair 2 vka2 vkb2" vk_tty2.log 2>&1)
  CRASH_RC=$?
  CRASH_TESTED=1
elif [ "$(uname)" = "Darwin" ]; then
  # see run_pty() above for why the feeder pipe is held open past the write
  CRASH_OUT=$( { printf 'y\n'; sleep 0.3; } | OTP_TEST_CRASH_POINT=during_key_truncate script -q vk_tty2.log sh -c "./bin/otp --new-key-pair 2 vka2 vkb2" 2>&1)
  CRASH_RC=$?
  CRASH_TESTED=1
fi
rm -f vk_tty2.log

if [ -z "$CRASH_TESTED" ]; then
  echo "     - SKIP - no way to allocate a pseudo-terminal on this platform"
else
  if [ "$CRASH_RC" = "77" ]; then
    echo "     - ${GREEN}PASS${NC} - simulated crash landed mid-truncate, as intended"
  else
    echo "     ! ${RED}FAIL${NC} - simulated crash did not trigger as expected (exit $CRASH_RC): $CRASH_OUT"
    exit 1
  fi

  PENDING_COUNT=$(ls .keychain/_randomness_pending_vka2_vkb2.bin 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PENDING_COUNT" = "1" ] && [ ! -e vka2_keys ] && [ ! -e vkb2_keys ]; then
    echo "     - ${GREEN}PASS${NC} - claim was durably staged before the simulated crash, no key files yet"
  else
    echo "     ! ${RED}FAIL${NC} - expected exactly one pending claim artifact and no key files"
    exit 1
  fi

  # A plain rerun (no pipe, no crash var) with the SAME size and names must
  # recover: no prompt (the claim is already paid for), finish the vault
  # truncation, and deliver the correct key files.
  run_pty "" --new-key-pair 2 vka2 vkb2
  if [ "$TTY_RC" = "0" ] && ! printf '%s' "$TTY_OUT" | grep -q "Use randomness vault for key generation?"; then
    echo "     - ${GREEN}PASS${NC} - recovery run succeeded without re-prompting"
  else
    echo "     ! ${RED}FAIL${NC} - recovery run should succeed silently (no prompt), got (rc=$TTY_RC): $TTY_OUT"
    exit 1
  fi

  dd if=vk_vault_full2.bin of=vk_pad1b.bin bs=1048576 count=2 2>/dev/null
  dd if=vk_vault_full2.bin of=vk_pad2b.bin bs=1048576 skip=2 count=2 2>/dev/null

  if cmp -s vka2_keys/encryption_for_vkb2.key vk_pad1b.bin &&
     cmp -s vkb2_keys/decryption_from_vka2.key vk_pad1b.bin &&
     cmp -s vka2_keys/decryption_from_vkb2.key vk_pad2b.bin &&
     cmp -s vkb2_keys/encryption_for_vka2.key vk_pad2b.bin; then
    echo "     - ${GREEN}PASS${NC} - recovered key files match the originally-claimed vault bytes exactly"
  else
    echo "     ! ${RED}FAIL${NC} - recovered key files do not match the claim that survived the crash"
    exit 1
  fi

  if [ "$(wc -c < .keychain/_randomness | tr -d ' ')" = "2097152" ]; then
    echo "     - ${GREEN}PASS${NC} - vault correctly drained by exactly 4 MB, once (no double-truncation)"
  else
    echo "     ! ${RED}FAIL${NC} - vault size wrong after crash recovery"
    exit 1
  fi

  PENDING_LEFT=$(ls .keychain/_randomness_pending_* 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PENDING_LEFT" = "0" ]; then
    echo "     - ${GREEN}PASS${NC} - pending claim artifact removed once delivered"
  else
    echo "     ! ${RED}FAIL${NC} - pending claim artifact left behind after recovery"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -rf .keychain vka_keys vkb_keys vka2_keys vkb2_keys
rm -f vk_*
echo ""
exit 0
