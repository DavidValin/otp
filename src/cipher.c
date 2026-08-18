/*****************************************************************************\
 *                                                                           *
 *   cipher.c - Encrypt/decrypt operations for OTP contacts                  *
 *                                                                           *
 *   The streaming XOR engine and everything that guards each operation:    *
 *   the crash-safe three-step commit ordering, the delivery-confirmation    *
 *   gate, the last-payload safety copies and consumed-key truncation.       *
 *   Contact and keychain bookkeeping live in keychain.c; the few pieces     *
 *   shared across that boundary are declared in keychain.h.                 *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "cipher.h"
#include "keychain.h"
#include "commit.h"
#include "compat.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

// Platform-specific includes
#ifdef _WIN32
#include <io.h>
#include <process.h>
// Windows compatibility mappings - the same mapping keychain.c and
// commit.c already make
#define unlink(path) _unlink(path)
#define PATH_SEPARATOR '\\'
#define getpid _getpid
#define O_BINARY_FLAG _O_BINARY
#ifndef _MSC_VER
#define fileno _fileno
#define open _open
#define close _close
#define fdopen _fdopen
#endif
#else
#include <unistd.h>
#define PATH_SEPARATOR '/'
#define O_BINARY_FLAG 0
#endif

// Is stdout an interactive terminal? Decides whether the post-delivery
// stderr report needs to open with a blank line: on a shared terminal the
// payload just written to stdout is raw bytes with no trailing newline,
// so without it the report starts mid-ciphertext on the same line. When
// stdout is redirected (the normal scripted use) no separation is needed
// - stderr is on its own device and must stay exactly as before.
#ifdef _WIN32
#define keychain_stdout_is_tty() _isatty(_fileno(stdout))
#define keychain_stderr_is_tty() _isatty(_fileno(stderr))
#else
#define keychain_stdout_is_tty() isatty(fileno(stdout))
#define keychain_stderr_is_tty() isatty(fileno(stderr))
#endif

// ANSI colors for the post-delivery report and the delivery-confirmation
// prompt; emitted only when stderr itself is a terminal, so captured or
// redirected stderr stays plain text for scripts and logs.
#define KEYCHAIN_GREEN "\x1b[32m"
#define KEYCHAIN_RED "\x1b[31m"
#define KEYCHAIN_YELLOW "\x1b[33m"
#define KEYCHAIN_RESET "\x1b[0m"

// Stream a fully-staged, verified pending artifact to the real output.
// This is the only place ciphertext/plaintext ever reaches the caller's
// stream - by the time it's called, the bytes being sent have already
// been durably and verifiably written to disk, so this step can fail or
// be interrupted freely: nothing about key state depends on it succeeding.
static int deliver_pending_file(const char *path, FILE *output)
{
  FILE *pf = fopen(path, "rb");
  if (!pf)
  {
    fprintf(stderr, "Error: Cannot open %s for delivery: %s\n", path, strerror(errno));
    return -1;
  }
  unsigned char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), pf)) > 0)
  {
    if (fwrite(buf, 1, n, output) != n)
    {
      fprintf(stderr, "Error: Failed to write output: %s\n", strerror(errno));
      fclose(pf);
      return -1;
    }
  }
  int had_error = ferror(pf);
  fclose(pf);
  if (had_error)
  {
    fprintf(stderr, "Error: Failed reading staged output %s\n", path);
    return -1;
  }

  // Flush before reporting success. fwrite() only moves bytes into the
  // stdio buffer, so for a message smaller than that buffer nothing has
  // reached the operating system yet, and the implicit flush at process
  // exit has nowhere to report a failure to. Skipping this check makes a
  // delivery onto a full disk look like success: the caller goes on to
  // delete the verified copy, leaving the message gone and its key
  // already spent - on the decrypt side, unrecoverably.
  if (fflush(output) != 0 || ferror(output))
  {
    fprintf(stderr, "Error: Failed to write output: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Last-payload safety copies: <keychain_dir>/<contact>.last_sent (the
// exact ciphertext the last encrypt wrote to stdout) and
// <keychain_dir>/<contact>.last_received (the exact plaintext the last
// decrypt wrote to stdout).
//
// The payload on stdout is the only product of an operation, and the key
// bytes that produced it are destroyed in the same run - so a user who
// forgets to redirect stdout (or loses the file) has lost the message
// unrecoverably. Each operation therefore keeps its delivered payload as
// a copy in the keychain directory. The copy is removed at the one
// moment it is provably no longer needed: when the NEXT operation in the
// same direction passes the delivery-confirmation gate (an interactive
// "yes", or -y/OTP_ASSUME_DELIVERED, both of which assert the previous
// message arrived intact). When the gate is instead answered "no", the
// operator is offered recovery of the kept copy to a file of their
// choosing, and the copy stays either way.
// ---------------------------------------------------------------------------

static void last_copy_path(const char *keychain_dir, const char *contact_name,
                           int is_encrypt, char *path, size_t path_size)
{
  snprintf(path, path_size, "%s%c%s%s", keychain_dir, PATH_SEPARATOR, contact_name,
           is_encrypt ? ".last_sent" : ".last_received");
}

// Removing a contact must take every trace of message content with it -
// including the kept copies in both directions.
void cipher_discard_last_copies(const char *keychain_dir, const char *contact_name)
{
  char last[600];
  last_copy_path(keychain_dir, contact_name, 1, last, sizeof(last));
  unlink(last);
  last_copy_path(keychain_dir, contact_name, 0, last, sizeof(last));
  unlink(last);
}

// The delivery of the previous message in this direction has just been
// confirmed, so its kept copy has served its purpose. Also runs for a
// contact's first message (nothing to confirm): any copy present then is
// a stale leftover from a removed contact of the same name.
static void discard_confirmed_last_copy(const char *contact_name, int is_encrypt)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return;
  char path[600];
  last_copy_path(keychain_dir, contact_name, is_encrypt, path, sizeof(path));
  remove(path);
}

// Keep the just-delivered payload (already durably on disk at
// delivered_path, the published pending artifact) as this direction's
// safety copy - a rename, so no payload bytes are re-read or re-written.
// If the rename fails the artifact must still not stay behind under its
// pending name: the next run's reconciliation would redeliver it as if
// this delivery had never happened.
static void keep_last_copy(const char *keychain_dir, const char *contact_name,
                           int is_encrypt, const char *delivered_path)
{
  char last[600];
  last_copy_path(keychain_dir, contact_name, is_encrypt, last, sizeof(last));
  remove(last); // stale copy, if any; commit_publish also replaces atomically
  if (commit_publish(delivered_path, last) != 0)
  {
    fprintf(stderr,
            "Warning: could not keep a local copy of the delivered %s for '%s'; "
            "if you did not save the output, it is not recoverable from the keychain.\n",
            is_encrypt ? "ciphertext" : "plaintext", contact_name);
    commit_discard_path(delivered_path);
  }
}

// Normalize a y/N answer read from the terminal (or injected by a test
// hook): trim the newline, lowercase, accept "y"/"yes". Anything else -
// including an empty answer - is "no"; the default must be the safe
// direction.
static int answer_is_yes(char *answer)
{
  size_t len = strlen(answer);
  while (len > 0 && (answer[len - 1] == '\n' || answer[len - 1] == '\r'))
    answer[--len] = '\0';
  for (size_t i = 0; i < len; i++)
    if (answer[i] >= 'A' && answer[i] <= 'Z')
      answer[i] += 'a' - 'A';
  return strcmp(answer, "y") == 0 || strcmp(answer, "yes") == 0;
}

// Stream the kept copy to a caller-chosen destination file. The
// destination is created fresh (O_EXCL, 0600): recovery must never
// silently overwrite an existing file the user pointed at by mistake.
static int recover_copy_to(const char *src, const char *dst)
{
  FILE *in = fopen(src, "rb");
  if (!in)
  {
    fprintf(stderr, "Error: cannot open kept copy '%s': %s\n", src, strerror(errno));
    return -1;
  }
  int fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create '%s': %s\n", dst, strerror(errno));
    fclose(in);
    return -1;
  }
  FILE *out = fdopen(fd, "wb");
  if (!out)
  {
    fprintf(stderr, "Error: cannot write '%s': %s\n", dst, strerror(errno));
    close(fd);
    unlink(dst);
    fclose(in);
    return -1;
  }

  unsigned char buf[65536];
  size_t n;
  int failed = 0;
  while (!failed && (n = fread(buf, 1, sizeof(buf), in)) > 0)
  {
    if (fwrite(buf, 1, n, out) != n)
      failed = 1;
  }
  if (ferror(in))
    failed = 1;
  // fsync before success: a recovery the user trusts must actually be on
  // disk, for exactly the reasons copy_key_file() fsyncs key material.
  if (!failed && (fflush(out) != 0 || otp_fsync(fileno(out)) != 0))
    failed = 1;
  if (fclose(out) != 0)
    failed = 1;
  fclose(in);
  if (failed)
  {
    fprintf(stderr, "Error: failed writing '%s': %s\n", dst, strerror(errno));
    unlink(dst);
    return -1;
  }
  return 0;
}

// After a rejected delivery confirmation: offer to write the kept copy of
// the previous message's payload to a file. Interactive like the gate
// itself - the questions go to stderr and the answers are read from the
// terminal, never stdin (which carries message data). Test hooks
// OTP_TEST_RECOVER_ANSWER / OTP_TEST_RECOVER_PATH stand in for the two
// terminal reads; when the gate's own answer was injected
// (OTP_TEST_CONFIRM_ANSWER) but no recovery answer was, the offer
// defaults to "no" rather than falling back to a real terminal - a test
// run must never block on one.
static void offer_recover_last_copy(const char *contact_name, int is_encrypt)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return;
  char src[600];
  last_copy_path(keychain_dir, contact_name, is_encrypt, src, sizeof(src));

  unsigned long long src_size;
  if (otp_file_size(src, &src_size) != 0)
    return; // no kept copy (the previous operation predates this feature)

  const char *what = is_encrypt ? "ciphertext" : "plaintext";
  int test_mode = getenv("OTP_TEST_CONFIRM_ANSWER") != NULL;

  char answer[16] = {0};
  const char *test_answer = getenv("OTP_TEST_RECOVER_ANSWER");
  if (test_answer)
  {
    snprintf(answer, sizeof(answer), "%s", test_answer);
  }
  else if (!test_mode)
  {
    FILE *tty = getenv("OTP_TEST_NO_TTY") ? NULL : otp_open_tty();
    if (!tty)
    {
      fprintf(stderr, "A copy of that message's %s is kept at '%s'.\n", what, src);
      return;
    }
    fprintf(stderr, "Recover the previous message's %s (%llu bytes) to a file? [y/N]: ",
            what, src_size);
    if (!fgets(answer, sizeof(answer), tty))
      answer[0] = '\0';
    fclose(tty);
  }

  if (!answer_is_yes(answer))
  {
    fprintf(stderr, "The %s copy is kept at '%s' until a later run confirms delivery.\n",
            what, src);
    return;
  }

  char dst[512] = {0};
  const char *test_path = getenv("OTP_TEST_RECOVER_PATH");
  if (test_path)
  {
    snprintf(dst, sizeof(dst), "%s", test_path);
  }
  else if (!test_mode)
  {
    FILE *tty = getenv("OTP_TEST_NO_TTY") ? NULL : otp_open_tty();
    if (!tty)
    {
      fprintf(stderr, "A copy of that message's %s is kept at '%s'.\n", what, src);
      return;
    }
    fprintf(stderr, "Path to recover the %s to: ", what);
    if (!fgets(dst, sizeof(dst), tty))
      dst[0] = '\0';
    fclose(tty);
  }
  size_t dlen = strlen(dst);
  while (dlen > 0 && (dst[dlen - 1] == '\n' || dst[dlen - 1] == '\r'))
    dst[--dlen] = '\0';
  if (dlen == 0)
  {
    fprintf(stderr, "No path given; the %s copy is kept at '%s'.\n", what, src);
    return;
  }

  if (recover_copy_to(src, dst) == 0)
  {
    fprintf(stderr,
            "Recovered %llu bytes of %s to '%s'. The kept copy remains at '%s' "
            "until a later run confirms delivery.\n",
            src_size, what, dst, src);
  }
  else
  {
    fprintf(stderr, "Recovery failed; the %s copy is still kept at '%s'.\n", what, src);
  }
}

// ---------------------------------------------------------------------------
// Delivery-confirmation gate
//
// The ciphertext this tool emits is raw XOR output: it carries no
// sequence number, offset or length. Decryption simply consumes the
// front of the decryption key by however many bytes arrive, so within
// one direction the protocol is only correct if every message arrives in
// the order it was sent, complete, exactly once. A message that is lost,
// reordered, duplicated or truncated in transit makes the next decrypt
// XOR against the wrong key range - producing garbage with exit code 0
// while physically destroying the key bytes both messages needed, which
// leaves them permanently unrecoverable.
//
// The program cannot see the transport, so that in-order property is
// only verifiable by the correspondents themselves, out of band. This
// gate makes that verification an enforced checkpoint instead of a
// silent assumption: before key is spent on any message after the first
// in a direction, the operator must confirm on the terminal that the
// previous message in that direction arrived and decoded correctly.
// Anything but an explicit yes cancels the operation.
//
// Placement in the callers is load-bearing: the prompt runs after the
// output is fully staged and verified but BEFORE commit_publish - i.e.
// before the first of the three durable commit steps - so a "no" (or an
// unanswerable prompt) aborts with the staging file as the only thing to
// discard and provably zero key consumed.
//
// The answer is read from the controlling terminal (otp_open_tty), never
// from stdin, which carries the message payload itself. With no terminal
// available the operation fails closed - assuming "yes" in exactly the
// unattended contexts most likely to replay or reorder input would gut
// the protection. Scripts state the confirmation explicitly instead,
// with -y/--assume-delivered or OTP_ASSUME_DELIVERED=1.
// ---------------------------------------------------------------------------

static int g_assume_delivered = 0;

void keychain_set_assume_delivered(int yes)
{
  g_assume_delivered = yes;
}

// Returns 0 when the operation may proceed and -1 when it must be
// cancelled. `prev_seq` is the sequence number of the last committed
// message in this direction (0 = none yet, nothing to confirm) and
// `next_off` is where that message's key range ended, which is exactly
// where this one's begins.
static int confirm_previous_delivery(const char *contact_name, int is_encrypt,
                                     size_t prev_seq, time_t prev_when,
                                     size_t next_seq, size_t next_off,
                                     size_t next_len)
{
  if (g_assume_delivered || getenv("OTP_ASSUME_DELIVERED"))
  {
    // -y is the operator's assertion that the previous message arrived
    // intact - the same confirmation as an interactive "yes", so the
    // kept copy of that message is no longer needed.
    discard_confirmed_last_copy(contact_name, is_encrypt);
    return 0;
  }
  if (prev_seq == 0)
  {
    // First message in this direction - nothing to confirm yet. Any kept
    // copy present now is a stale leftover (removed contact, same name).
    discard_confirmed_last_copy(contact_name, is_encrypt);
    return 0;
  }

  char when[64];
  if (prev_when > 0)
  {
    struct tm tm_struct;
#ifdef _WIN32
    localtime_s(&tm_struct, &prev_when);
#else
    localtime_r(&prev_when, &tm_struct);
#endif
    strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm_struct);
  }
  else
  {
    snprintf(when, sizeof(when), "unknown time");
  }

  // Colors only when stderr is a terminal (the prompt is interactive by
  // nature, but tests capture it to files and must see plain text). The
  // yellow contact name inside the red WARNING block switches straight
  // from red to yellow and back - both are foreground colors, so no
  // reset is needed in between.
  int gate_tty = keychain_stderr_is_tty();
  const char *red = gate_tty ? KEYCHAIN_RED : "";
  const char *yellow = gate_tty ? KEYCHAIN_YELLOW : "";
  const char *creset = gate_tty ? KEYCHAIN_RESET : "";

  fprintf(stderr,
          "%sConfirmation required%s for contact '%s%s%s' before more key is spent.\n"
          "  Previous %s message: #%zu, %s %s, key consumed up to offset %zu.\n"
          "  This run will %s message #%zu using key bytes %zu-%zu (%zu bytes),\n"
          "  which are destroyed after use.\n",
          red, creset, yellow, contact_name, creset,
          is_encrypt ? "sent" : "received",
          prev_seq,
          is_encrypt ? "sent" : "received",
          when, next_off,
          is_encrypt ? "encrypt" : "decrypt",
          next_seq, next_off, next_off + next_len, next_len);
  if (is_encrypt)
  {
    fprintf(stderr,
            "  %sWARNING: If %s%s%s hasn't received the previous message and you send another\n"
            "  one they might lose track of the correct offset to use%s\n",
            red, yellow, contact_name, red, creset);
  }
  else
  {
    fprintf(stderr,
            "  %sWARNING: If the previous message from %s%s%s was not decoded correctly and\n"
            "  you decrypt another one you might lose track of the correct offset to use%s\n",
            red, yellow, contact_name, red, creset);
  }

  char answer[16] = {0};

  // Test-only injection of the operator's answer, in the same family as
  // the other OTP_TEST_* hooks: it stands in for the terminal read below
  // so tests can exercise both answers deterministically. A no-op when
  // unset. OTP_TEST_NO_TTY likewise simulates a process with no
  // controlling terminal, to prove the fail-closed branch.
  const char *test_answer = getenv("OTP_TEST_CONFIRM_ANSWER");
  if (test_answer)
  {
    snprintf(answer, sizeof(answer), "%s", test_answer);
  }
  else
  {
    FILE *tty = getenv("OTP_TEST_NO_TTY") ? NULL : otp_open_tty();
    if (!tty)
    {
      fprintf(stderr,
              "Error: this confirmation must be answered on the terminal (stdin carries the "
              "message data), and no terminal is available. Confirm with your correspondent "
              "out of band that the previous message arrived intact, then re-run with "
              "-y/--assume-delivered (or OTP_ASSUME_DELIVERED=1). Cancelled; no key material "
              "was consumed.\n");
      return -1;
    }
    if (is_encrypt)
      fprintf(stderr,
              "Was the previous message delivered and decoded correctly by %s%s%s? [y/N]: ",
              yellow, contact_name, creset);
    else
      fprintf(stderr,
              "Was the previous message from %s%s%s delivered and decoded correctly? [y/N]: ",
              yellow, contact_name, creset);
    if (!fgets(answer, sizeof(answer), tty))
      answer[0] = '\0'; // EOF on the terminal counts as "no"
    fclose(tty);
  }

  if (answer_is_yes(answer))
  {
    // Delivery of the previous message is confirmed; its kept copy has
    // served its purpose.
    discard_confirmed_last_copy(contact_name, is_encrypt);
    return 0;
  }

  if (is_encrypt)
  {
    fprintf(stderr,
            "\n\n%sCancelled!%s No key material was consumed. If the previous ciphertext was lost in "
            "transit, re-send the saved ciphertext file - its bytes are still valid for the "
            "recipient's current key position. If the recipient decrypted it to garbage, this "
            "direction is out of sync: re-key the contact (remove and re-add with fresh keys) "
            "before sending anything else.\n",
            red, creset);
  }
  else
  {
    fprintf(stderr,
            "\n\n%sCancelled!%s No key material was consumed. If the previous message decrypted to "
            "garbage, this direction is out of sync (a message was lost, reordered, duplicated "
            "or truncated in transit): re-key the contact (remove and re-add with fresh keys) "
            "before decrypting anything else.\n",
            red, creset);
  }
  // The rejected message's payload may still be needed (e.g. to re-send
  // the saved ciphertext); offer to write the kept copy to a file.
  offer_recover_last_copy(contact_name, is_encrypt);
  return -1;
}

// Reconcile the remaining-key size recorded in metadata against the key
// file's actual size, and adopt the file's.
//
// The key file - not the metadata - is the authority on how much key
// material is left: bytes are consumed from the front and the file is
// physically truncated, so its size *is* the remaining length. Metadata
// can nevertheless drift from it - a restored backup, a hand-edit - and
// without re-deriving the truth from the file, such a keychain would
// fail every subsequent operation with "Failed to read remaining key"
// and never recover on its own.
//
// Adopting the file's size is only safe in one direction. A key file
// *smaller* than metadata claims means the metadata is merely behind:
// take the file's size and continue. A key file *larger* than metadata
// claims cannot arise from any code path here - key files only ever
// shrink - so it means key material was rolled back or restored from an
// older copy. Continuing there would encrypt with bytes that have
// already been used, which is the one-time-pad failure this whole module
// exists to prevent, so that case is refused loudly rather than healed.
static int resync_key_size(const char *direction, const char *contact_name,
                           const char *keychain_dir, Contact *c,
                           const char *key_path, size_t *declared_size)
{
  unsigned long long actual_64;
  if (otp_file_size(key_path, &actual_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat %s key file '%s' for contact '%s': %s\n",
            direction, key_path, contact_name, strerror(errno));
    return -1;
  }
  size_t actual;
  if (otp_size_to_size_t(actual_64, &actual) != 0)
  {
    // Can only happen on a 32-bit build opening a keychain written by a
    // 64-bit one; truncating would fake a key-shrunk/key-grown verdict.
    fprintf(stderr, "Error: %s key file '%s' for contact '%s' is too large for this build\n",
            direction, key_path, contact_name);
    return -1;
  }

  if (actual == *declared_size)
    return 0;

  if (actual > *declared_size)
  {
    fprintf(stderr,
            "Error: %s key file '%s' for contact '%s' holds %zu bytes but its metadata records only "
            "%zu remaining. Key files only ever shrink, so this means key material was restored or "
            "rolled back to an older copy. Refusing to continue: the extra bytes at the front of the "
            "file have already been used once, and using them again would break the one-time pad. "
            "Re-key this contact (remove it and add it again with fresh keys) to proceed.\n",
            direction, key_path, contact_name, actual, *declared_size);
    return -1;
  }

  fprintf(stderr,
          "Note: %s key metadata for contact '%s' recorded %zu bytes remaining but the key file holds "
          "%zu; adopting the key file's size, which is authoritative.\n",
          direction, contact_name, *declared_size, actual);
  *declared_size = actual;

  // Persist the correction now rather than relying on the end of this
  // operation, so a keychain that has drifted is repaired even if the
  // current operation goes on to fail for an unrelated reason.
  if (save_contact_meta(keychain_dir, c) != 0)
  {
    fprintf(stderr, "Error: Failed to record corrected key size for contact '%s'\n", contact_name);
    return -1;
  }
  return 0;
}

// Drop the consumed prefix from a key file: stream everything from
// `consumed` onward into a staging file, verify that staged copy by
// read-back, then atomically publish it over the key file.
//
// The remainder is streamed in fixed-size chunks and never held whole in
// memory: it can be nearly the entire key, so buffering it would make
// peak memory scale with key size and cap this tool at keys that fit in
// RAM - on a 1TB key, sending one short message would need a ~1TB
// allocation.
#define KEY_STREAM_CHUNK (4 * 1024 * 1024)
int truncate_key_file(const char *direction, const char *key_path,
                      size_t consumed, size_t remaining_size)
{
  FILE *keyfile = fopen(key_path, "rb");
  if (!keyfile || otp_fseek(keyfile, consumed) != 0)
  {
    fprintf(stderr, "Error: Failed to reopen %s key for truncation: %s\n",
            direction, strerror(errno));
    if (keyfile)
      fclose(keyfile);
    return -1;
  }

  char tmp_path[600];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", key_path);

  CommitStage stage;
  if (commit_stage_open(&stage, tmp_path) != 0)
  {
    fclose(keyfile);
    return -1;
  }

  unsigned char *buf = malloc(KEY_STREAM_CHUNK);
  if (!buf)
  {
    fprintf(stderr, "Error: Memory allocation failed while truncating %s key\n", direction);
    fclose(keyfile);
    commit_stage_abort(&stage);
    return -1;
  }

  size_t left = remaining_size;
  while (left > 0)
  {
    size_t want = (left < KEY_STREAM_CHUNK) ? left : KEY_STREAM_CHUNK;
    size_t got = fread(buf, 1, want, keyfile);
    if (got != want)
    {
      fprintf(stderr, "Error: Failed to read remaining %s key\n", direction);
      free(buf);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }
    if (commit_stage_write(&stage, buf, got) != 0)
    {
      free(buf);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }
    commit_test_crash_point("during_key_truncate");
    left -= got;
  }

  free(buf);
  fclose(keyfile);

  if (commit_stage_close_verified(&stage) != 0)
    return -1;

  return commit_publish(stage.tmp_path, key_path);
}

// Encrypt with contact's encryption key
//
// Key consumption is committed in three atomic, verified steps, strictly
// in this order, before the ciphertext is ever delivered to `output`:
//   1. the finished ciphertext is staged and published as a "pending
//      artifact" tagged with the exact key range it corresponds to
//   2. the key file is truncated to remove the consumed prefix
//   3. the contact's .meta file is updated to match
// Only key-file-before-.meta ordering is safe: if it were reversed, a
// crash between the two would leave the .meta believing a key range is
// spent while the key file still contains those exact bytes, unread and
// reusable - a two-time-pad break. With this ordering, the same crash
// instead leaves the key file already reduced (correct) and the .meta
// merely stale, which commit_reconcile() can always finish
// deterministically using the pending artifact's own filename tag.
// See the "Crash-safe key consumption" section of README.md.
//
// Runs under an exclusive, per-contact lock (see contact_lock_acquire in
// commit.c) so that two processes racing to encrypt for the same contact
// can't each independently read and consume the same key bytes - a race
// the staging/verification mechanism alone cannot detect, since both
// would produce individually valid, individually verified output.
static int encrypt_with_contact_locked(Contact *c, const char *contact_name,
                                        const char *keychain_dir,
                                        FILE *input, FILE *output)
{
  if (c->EncryptionKeyPath[0] == '\0')
  {
    fprintf(stderr, "Error: Contact '%s' has no encryption key\n", contact_name);
    return -1;
  }

  // Recover from any operation an earlier run left incomplete before
  // doing anything else.
  CommitRecovery rec;
  if (commit_reconcile(keychain_dir, contact_name, "enc", c->EncryptionKeyPath,
                        c->EncryptionKeyOffset, c->EncryptionKeySize,
                        c->EncryptedSequence, &rec) != 0)
  {
    // COMMIT_RECOVER_BLOCKED: the key file could not be read, so the
    // pending artifact was kept. Abort rather than continue - staging
    // new output next to a kept artifact would get one of them
    // discarded as an "unexpected extra" on the next reconciliation.
    fprintf(stderr,
            "Error: cannot reconcile the pending encryption artifact for '%s'; "
            "it was kept - resolve the key file problem and run again\n",
            contact_name);
    return -1;
  }

  if (rec.action == COMMIT_RECOVER_ERROR)
  {
    fprintf(stderr, "Warning: discarded an unrecoverable pending encryption artifact for '%s'\n", contact_name);
  }
  else if (rec.action == COMMIT_RECOVER_DISCARD)
  {
    fprintf(stderr,
            "Note: discarded an uncommitted pending encryption for '%s' left by an interrupted run; "
            "no key material was used or lost.\n",
            contact_name);
  }
  else if (rec.action == COMMIT_RECOVER_FINISH || rec.action == COMMIT_RECOVER_DELIVER)
  {
    if (rec.action == COMMIT_RECOVER_FINISH)
    {
      c->EncryptionKeyOffset = rec.corrected_offset;
      c->EncryptionKeySize = rec.corrected_size;
      c->EncryptedSequence = rec.sequence;
      if (save_contact_meta(keychain_dir, c) != 0)
      {
        fprintf(stderr, "Error: Failed to finish interrupted commit for '%s'\n", contact_name);
        return -1;
      }
    }

    fprintf(stderr,
            "Recovered incomplete delivery for contact '%s' (message #%zu, key range %zu-%zu): "
            "redelivering the previously computed ciphertext now instead of processing new input. "
            "Run the command again to encrypt new input.\n",
            contact_name, rec.sequence, rec.range_offset, rec.range_offset + rec.range_length);

    if (deliver_pending_file(rec.pending_path, output) != 0)
    {
      fprintf(stderr, "Error: Failed to redeliver recovered ciphertext for '%s'\n", contact_name);
      return -1;
    }
    keep_last_copy(keychain_dir, contact_name, 1, rec.pending_path);
    return KEYCHAIN_REDELIVERED;
  }

  // Metadata and key file must agree before any key is spent. Runs after
  // reconciliation, which is the one place a legitimate mismatch is
  // expected and is resolved from the pending artifact instead.
  if (resync_key_size("encryption", contact_name, keychain_dir, c,
                      c->EncryptionKeyPath, &c->EncryptionKeySize) != 0)
    return -1;

  if (c->EncryptionKeySize == 0)
  {
    fprintf(stderr, "Error: No encryption key remaining for contact '%s'\n", contact_name);
    return -1;
  }

  // Offset 0 means the head on disk is still the head from add time, and
  // this operation is about to spend it for the first time. Record its
  // fingerprint in the spent-heads registry first, so a copy of the
  // original file stays recognizable if it is ever re-supplied after this
  // contact is removed. Fail closed: nothing has been read or spent yet,
  // so aborting here costs only a retry, while continuing unrecorded
  // would silently forfeit that protection forever.
  if (c->EncryptionKeyOffset == 0 &&
      spent_head_record(keychain_dir, "enc", c->EncryptionKeyPath) != 0)
  {
    fprintf(stderr,
            "Error: could not record the spent-key fingerprint for contact '%s'; "
            "aborting before any key material is spent\n",
            contact_name);
    return -1;
  }

  size_t available_key = c->EncryptionKeySize;

  // Open encryption key file (always read from beginning)
  FILE *keyfile = fopen(c->EncryptionKeyPath, "rb");
  if (!keyfile)
  {
    fprintf(stderr, "Error: Cannot open encryption key file '%s': %s\n",
            c->EncryptionKeyPath, strerror(errno));
    return -1;
  }

// Stream encryption in chunks (4MB at a time)
#define CHUNK_SIZE (4 * 1024 * 1024)
  unsigned char *chunk = malloc(CHUNK_SIZE);
  unsigned char *key_chunk = malloc(CHUNK_SIZE);
  if (!chunk || !key_chunk)
  {
    fprintf(stderr, "Error: Memory allocation failed\n");
    free(chunk);
    free(key_chunk);
    fclose(keyfile);
    return -1;
  }

  // Stage the ciphertext to a durable, per-process working file. It is
  // not yet delivered anywhere, and its final (tagged) name and any key
  // consumption are only decided once the whole message has been
  // processed and verified.
  char stage_tmp_path[560];
  snprintf(stage_tmp_path, sizeof(stage_tmp_path), "%s%c%s_enc_pending.%ld.tmp",
           keychain_dir, PATH_SEPARATOR, contact_name, (long)getpid());

  CommitStage stage;
  if (commit_stage_open(&stage, stage_tmp_path) != 0)
  {
    free(chunk);
    free(key_chunk);
    fclose(keyfile);
    return -1;
  }

  size_t total_bytes = 0;

  while (1)
  {
    // Read input chunk
    size_t input_bytes = fread(chunk, 1, CHUNK_SIZE, input);
    if (input_bytes == 0)
      break;

    // Check if we have enough key material
    if (total_bytes + input_bytes > available_key)
    {
      fprintf(stderr, "Error: Message size exceeds available encryption key size for contact '%s'\n",
              contact_name);
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    // Read key chunk
    size_t key_bytes = fread(key_chunk, 1, input_bytes, keyfile);
    if (key_bytes != input_bytes)
    {
      fprintf(stderr, "Error: Failed to read encryption key\n");
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    // XOR encryption
    for (size_t i = 0; i < input_bytes; i++)
    {
      chunk[i] ^= key_chunk[i];
    }

    // Write encrypted chunk to the staged file (not the real output yet)
    if (commit_stage_write(&stage, chunk, input_bytes) != 0)
    {
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    total_bytes += input_bytes;
  }

  fclose(keyfile);
  free(chunk);
  free(key_chunk);

  // fread() returns 0 both at end-of-input and on a read error, and the
  // two are not interchangeable here: on an error what was just staged is
  // a truncated prefix of the caller's message, and committing it would
  // spend key material on a partial message while reporting success.
  if (ferror(input))
  {
    fprintf(stderr, "Error: Failed reading input for contact '%s': %s\n",
            contact_name, strerror(errno));
    commit_stage_abort(&stage);
    return -1;
  }

  if (total_bytes == 0)
  {
    fprintf(stderr, "Error: No input data provided\n");
    commit_stage_abort(&stage);
    return -1;
  }

  if (commit_stage_close_verified(&stage) != 0)
  {
    return -1;
  }

  size_t new_sequence = c->EncryptedSequence + 1;
  size_t range_offset = c->EncryptionKeyOffset;

  // Delivery-confirmation gate: the operator must vouch that the previous
  // message reached the other side intact before this one's key range is
  // spent. Runs after staging so the exact range can be shown, but before
  // commit_publish - the first durable step - so cancelling only has the
  // staging file to discard and provably consumes no key.
  if (confirm_previous_delivery(contact_name, 1, c->EncryptedSequence,
                                c->LastMessageSentAt, new_sequence,
                                range_offset, total_bytes) != 0)
  {
    commit_discard_path(stage.tmp_path);
    return -1;
  }

  // Publish the verified ciphertext under its final, key-range-tagged
  // name. Nothing has been declared "spent" yet - this is just durable
  // evidence, safe to exist independently of what happens next.
  char pending_final_path[600];
  commit_pending_path(keychain_dir, contact_name, "enc", new_sequence,
                       range_offset, total_bytes, pending_final_path, sizeof(pending_final_path));

  if (commit_publish(stage.tmp_path, pending_final_path) != 0)
  {
    commit_discard_path(stage.tmp_path);
    return -1;
  }

  commit_test_crash_point("after_pending_publish");

  // Truncate consumed bytes from the key file: stream what remains into a
  // staging file, verify it, and only then publish it over the real key
  // file.
  size_t remaining_size = c->EncryptionKeySize - total_bytes;
  if (truncate_key_file("encryption", c->EncryptionKeyPath, total_bytes, remaining_size) != 0)
  {
    commit_discard_path(pending_final_path);
    return -1;
  }

  commit_test_crash_point("after_key_publish");

  // Update and commit the contact's .meta file (the key file is already
  // committed at this point - this is the second, final half of the pair).
  c->EncryptedSequence = new_sequence;
  c->EncryptionKeyOffset = range_offset + total_bytes;
  c->EncryptionKeySize = remaining_size;
  c->LastMessageSentAt = time(NULL);

  if (save_contact_meta(keychain_dir, c) != 0)
  {
    fprintf(stderr, "Error: Failed to save keychain\n");
    return -1;
  }

  commit_test_crash_point("after_keychain_save");

  // Both commits are durable. Delivery is now a freely-retryable step
  // that never needs to touch key material again.
  if (deliver_pending_file(pending_final_path, output) != 0)
  {
    fprintf(stderr, "Error: Failed to deliver encrypted data\n");
    return -1;
  }
  // Keep the delivered ciphertext as .keychain/<contact>.last_sent until
  // a later run confirms it arrived - see the last-payload block comment.
  keep_last_copy(keychain_dir, contact_name, 1, pending_final_path);

  // Print info to stderr, separated from the ciphertext by a blank line
  // when both share the terminal, and in green when stderr is a terminal
  if (keychain_stdout_is_tty())
    fprintf(stderr, "\n\n");
  {
    int err_tty = keychain_stderr_is_tty();
    fprintf(stderr, "%sUsed %zu bytes from encryption key for contact '%s'%s\n",
            err_tty ? KEYCHAIN_GREEN : "", total_bytes, contact_name,
            err_tty ? KEYCHAIN_RESET : "");
    fprintf(stderr, "%sRemaining encryption key: %zu bytes%s\n",
            err_tty ? KEYCHAIN_GREEN : "", c->EncryptionKeySize,
            err_tty ? KEYCHAIN_RESET : "");
  }

  return 0;
}

int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, contact_name) != 0)
    return -1;

  // Another process may have been holding this lock and have committed
  // changes for this contact while we were waiting for it. `c` (and the
  // rest of g_keychain) reflects whatever was on disk when *this*
  // process started, which can now be stale - reload from disk before
  // touching anything, so the operation runs against authoritative,
  // current state rather than a snapshot from before the wait.
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }
  c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    contact_lock_release(&lock);
    return -1;
  }

  int result = encrypt_with_contact_locked(c, contact_name, keychain_dir, input, output);

  contact_lock_release(&lock);
  return result;
}

// Decrypt with contact's decryption key
//
// Mirrors encrypt_with_contact's commit ordering exactly. This matters
// even more here: unlike ciphertext, the recovered plaintext cannot be
// re-derived once the corresponding decryption key bytes are gone, so
// staging the verified plaintext durably before committing key
// consumption is what stands between a crash and permanently
// unrecoverable message loss.
//
// Runs under the same per-contact lock as encrypt_with_contact - see its
// comment for why mutual exclusion is required here in addition to, not
// instead of, the crash-safety mechanism.
static int decrypt_with_contact_locked(Contact *c, const char *contact_name,
                                        const char *keychain_dir,
                                        FILE *input, FILE *output)
{
  if (c->DecryptionKeyPath[0] == '\0')
  {
    fprintf(stderr, "Error: Contact '%s' has no decryption key\n", contact_name);
    return -1;
  }

  CommitRecovery rec;
  if (commit_reconcile(keychain_dir, contact_name, "dec", c->DecryptionKeyPath,
                        c->DecryptionKeyOffset, c->DecryptionKeySize,
                        c->DecryptedSequence, &rec) != 0)
  {
    // COMMIT_RECOVER_BLOCKED: the key file could not be read. The kept
    // artifact is the ONLY copy of a recovered plaintext whose key
    // bytes are already spent - abort so a later run can reconcile and
    // redeliver it once the key file is readable again.
    fprintf(stderr,
            "Error: cannot reconcile the pending decryption artifact for '%s'; "
            "it was kept - resolve the key file problem and run again\n",
            contact_name);
    return -1;
  }

  if (rec.action == COMMIT_RECOVER_ERROR)
  {
    fprintf(stderr, "Warning: discarded an unrecoverable pending decryption artifact for '%s'\n", contact_name);
  }
  else if (rec.action == COMMIT_RECOVER_DISCARD)
  {
    fprintf(stderr,
            "Note: discarded an uncommitted pending decryption for '%s' left by an interrupted run; "
            "no key material was used or lost.\n",
            contact_name);
  }
  else if (rec.action == COMMIT_RECOVER_FINISH || rec.action == COMMIT_RECOVER_DELIVER)
  {
    if (rec.action == COMMIT_RECOVER_FINISH)
    {
      c->DecryptionKeyOffset = rec.corrected_offset;
      c->DecryptionKeySize = rec.corrected_size;
      c->DecryptedSequence = rec.sequence;
      if (save_contact_meta(keychain_dir, c) != 0)
      {
        fprintf(stderr, "Error: Failed to finish interrupted commit for '%s'\n", contact_name);
        return -1;
      }
    }

    fprintf(stderr,
            "Recovered incomplete delivery for contact '%s' (message #%zu, key range %zu-%zu): "
            "redelivering the previously decrypted plaintext now instead of processing new input. "
            "Run the command again to decrypt new input.\n",
            contact_name, rec.sequence, rec.range_offset, rec.range_offset + rec.range_length);

    if (deliver_pending_file(rec.pending_path, output) != 0)
    {
      fprintf(stderr, "Error: Failed to redeliver recovered plaintext for '%s'\n", contact_name);
      return -1;
    }
    keep_last_copy(keychain_dir, contact_name, 0, rec.pending_path);
    return KEYCHAIN_REDELIVERED;
  }

  if (resync_key_size("decryption", contact_name, keychain_dir, c,
                      c->DecryptionKeyPath, &c->DecryptionKeySize) != 0)
    return -1;

  if (c->DecryptionKeySize == 0)
  {
    fprintf(stderr, "Error: No decryption key remaining for contact '%s'\n", contact_name);
    return -1;
  }

  // First consumption of this key - record its head in the spent-heads
  // registry before anything is spent. See encrypt_with_contact_locked
  // for why this must happen first and must fail closed.
  if (c->DecryptionKeyOffset == 0 &&
      spent_head_record(keychain_dir, "dec", c->DecryptionKeyPath) != 0)
  {
    fprintf(stderr,
            "Error: could not record the spent-key fingerprint for contact '%s'; "
            "aborting before any key material is spent\n",
            contact_name);
    return -1;
  }

  size_t available_key = c->DecryptionKeySize;

  // Open decryption key file (always read from beginning)
  FILE *keyfile = fopen(c->DecryptionKeyPath, "rb");
  if (!keyfile)
  {
    fprintf(stderr, "Error: Cannot open decryption key file '%s': %s\n",
            c->DecryptionKeyPath, strerror(errno));
    return -1;
  }

  // Stream decryption in chunks (4MB at a time)
  unsigned char *chunk = malloc(CHUNK_SIZE);
  unsigned char *key_chunk = malloc(CHUNK_SIZE);
  if (!chunk || !key_chunk)
  {
    fprintf(stderr, "Error: Memory allocation failed\n");
    free(chunk);
    free(key_chunk);
    fclose(keyfile);
    return -1;
  }

  char stage_tmp_path[560];
  snprintf(stage_tmp_path, sizeof(stage_tmp_path), "%s%c%s_dec_pending.%ld.tmp",
           keychain_dir, PATH_SEPARATOR, contact_name, (long)getpid());

  CommitStage stage;
  if (commit_stage_open(&stage, stage_tmp_path) != 0)
  {
    free(chunk);
    free(key_chunk);
    fclose(keyfile);
    return -1;
  }

  size_t total_bytes = 0;

  while (1)
  {
    // Read input chunk
    size_t input_bytes = fread(chunk, 1, CHUNK_SIZE, input);
    if (input_bytes == 0)
      break;

    // Check if we have enough key material
    if (total_bytes + input_bytes > available_key)
    {
      fprintf(stderr, "Error: Message size exceeds available decryption key size for contact '%s'\n",
              contact_name);
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    // Read key chunk
    size_t key_bytes = fread(key_chunk, 1, input_bytes, keyfile);
    if (key_bytes != input_bytes)
    {
      fprintf(stderr, "Error: Failed to read decryption key\n");
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    // XOR decryption
    for (size_t i = 0; i < input_bytes; i++)
    {
      chunk[i] ^= key_chunk[i];
    }

    // Write decrypted chunk to the staged file (not the real output yet)
    if (commit_stage_write(&stage, chunk, input_bytes) != 0)
    {
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    total_bytes += input_bytes;
  }

  fclose(keyfile);
  free(chunk);
  free(key_chunk);

  // fread() returns 0 both at end-of-input and on a read error, and the
  // two are not interchangeable here: on an error what was just staged is
  // a truncated prefix of the caller's message, and committing it would
  // spend key material on a partial message while reporting success.
  if (ferror(input))
  {
    fprintf(stderr, "Error: Failed reading input for contact '%s': %s\n",
            contact_name, strerror(errno));
    commit_stage_abort(&stage);
    return -1;
  }

  if (total_bytes == 0)
  {
    fprintf(stderr, "Error: No input data provided\n");
    commit_stage_abort(&stage);
    return -1;
  }

  if (commit_stage_close_verified(&stage) != 0)
  {
    return -1;
  }

  size_t new_sequence = c->DecryptedSequence + 1;
  size_t range_offset = c->DecryptionKeyOffset;

  // Same delivery-confirmation gate as the encrypt side, and it matters
  // even more here: decrypting input that is out of order, duplicated or
  // truncated would XOR against the wrong key range, emit garbage with
  // exit 0, and destroy the key bytes the real message needs. Confirming
  // the previous plaintext was correct caps a desynchronized channel at
  // one bad message instead of a silent cascade.
  if (confirm_previous_delivery(contact_name, 0, c->DecryptedSequence,
                                c->LastMessageReceivedAt, new_sequence,
                                range_offset, total_bytes) != 0)
  {
    commit_discard_path(stage.tmp_path);
    return -1;
  }

  char pending_final_path[600];
  commit_pending_path(keychain_dir, contact_name, "dec", new_sequence,
                       range_offset, total_bytes, pending_final_path, sizeof(pending_final_path));

  if (commit_publish(stage.tmp_path, pending_final_path) != 0)
  {
    commit_discard_path(stage.tmp_path);
    return -1;
  }

  commit_test_crash_point("after_pending_publish");

  // Truncate consumed bytes from the key file (streamed - see
  // truncate_key_file)
  size_t remaining_size = c->DecryptionKeySize - total_bytes;
  if (truncate_key_file("decryption", c->DecryptionKeyPath, total_bytes, remaining_size) != 0)
  {
    commit_discard_path(pending_final_path);
    return -1;
  }

  commit_test_crash_point("after_key_publish");

  // Update contact metadata
  c->DecryptedSequence = new_sequence;
  c->DecryptionKeyOffset = range_offset + total_bytes;
  c->DecryptionKeySize = remaining_size;
  c->LastMessageReceivedAt = time(NULL);

  // Commit the contact's .meta file (the key file is already committed at
  // this point - this is the second, final half of the pair).
  if (save_contact_meta(keychain_dir, c) != 0)
  {
    fprintf(stderr, "Error: Failed to save keychain\n");
    return -1;
  }

  commit_test_crash_point("after_keychain_save");

  if (deliver_pending_file(pending_final_path, output) != 0)
  {
    fprintf(stderr, "Error: Failed to deliver decrypted data\n");
    return -1;
  }
  // Keep the delivered plaintext as .keychain/<contact>.last_received
  // until a later run confirms it - see the last-payload block comment.
  keep_last_copy(keychain_dir, contact_name, 0, pending_final_path);

  // Print info to stderr, separated from the plaintext by a blank line
  // when both share the terminal, and in green when stderr is a terminal
  if (keychain_stdout_is_tty())
    fprintf(stderr, "\n\n");
  {
    int err_tty = keychain_stderr_is_tty();
    fprintf(stderr, "%sUsed %zu bytes from decryption key for contact '%s'%s\n",
            err_tty ? KEYCHAIN_GREEN : "", total_bytes, contact_name,
            err_tty ? KEYCHAIN_RESET : "");
    fprintf(stderr, "%sRemaining decryption key: %zu bytes%s\n",
            err_tty ? KEYCHAIN_GREEN : "", c->DecryptionKeySize,
            err_tty ? KEYCHAIN_RESET : "");
  }

  return 0;
}

int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, contact_name) != 0)
    return -1;

  // See the matching comment in encrypt_with_contact: reload from disk
  // now that we hold the lock, since another process may have committed
  // changes for this contact while we were waiting for it.
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }
  c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    contact_lock_release(&lock);
    return -1;
  }

  int result = decrypt_with_contact_locked(c, contact_name, keychain_dir, input, output);

  contact_lock_release(&lock);
  return result;
}

// ---------------------------------------------------------------------------
// --status / --recover-last: the read-only query surface for external
// integrations (see the "External Integrations" section of README.md).
//
// An integrated program driving otp needs, per contact and direction,
// exactly the answers the operational paths already derive from disk on
// every run: is a crash-recovery redelivery pending (the next operation
// would re-emit a committed earlier message instead of processing its
// input), is the last delivered message still awaiting the out-of-band
// delivery confirmation, how much key physically remains, and do the
// .meta declarations agree with the key file. --status computes all of
// that with the same primitives the operations use - commit_classify()
// shares its truth table with commit_reconcile(), and the key file's
// physical size is the authority exactly as in resync_key_size() - but
// performs none of their actions: no sweep, no discard, no self-heal, no
// deletion. Both commands run under the contact lock so the snapshot
// cannot interleave with a live operation.
// ---------------------------------------------------------------------------

typedef struct
{
  size_t sequence;                  // messages committed in this direction
  unsigned long long key_remaining; // physical key file size - the authority
  const char *meta_state;           // "consistent" | "meta_behind" | "rolled_back"
  int redelivery_pending;           // next op will redeliver, not process input
  size_t pending_sequence;          // the artifact's filename tag, when pending
  size_t pending_offset;
  size_t pending_length;
  int ack_outstanding;              // kept last-payload copy exists
  char copy_path[600];
} DirStatus;

static int status_direction(const char *keychain_dir, Contact *c,
                            int is_encrypt, DirStatus *out)
{
  const char *key_path = is_encrypt ? c->EncryptionKeyPath : c->DecryptionKeyPath;
  size_t declared_offset = is_encrypt ? c->EncryptionKeyOffset : c->DecryptionKeyOffset;
  size_t declared_size = is_encrypt ? c->EncryptionKeySize : c->DecryptionKeySize;

  memset(out, 0, sizeof(*out));
  out->sequence = is_encrypt ? c->EncryptedSequence : c->DecryptedSequence;
  out->meta_state = "consistent";

  last_copy_path(keychain_dir, c->Name, is_encrypt, out->copy_path, sizeof(out->copy_path));
  unsigned long long copy_size;
  out->ack_outstanding = (otp_file_size(out->copy_path, &copy_size) == 0);

  if (key_path[0] == '\0')
    return 0; // no key in this direction - nothing else to verify

  unsigned long long physical;
  if (otp_file_size(key_path, &physical) != 0)
  {
    fprintf(stderr, "Error: cannot stat %s key file '%s' for contact '%s': %s\n",
            is_encrypt ? "encryption" : "decryption", key_path, c->Name, strerror(errno));
    return -1;
  }
  out->key_remaining = physical;

  CommitStatus cs;
  if (commit_classify(keychain_dir, c->Name, is_encrypt ? "enc" : "dec",
                      key_path, declared_offset, declared_size, &cs) != 0)
  {
    fprintf(stderr,
            "Error: cannot classify the pending %s artifact for contact '%s' "
            "(key file unreadable); nothing can be concluded about this direction\n",
            is_encrypt ? "encryption" : "decryption", c->Name);
    return -1;
  }

  if (cs.action == COMMIT_RECOVER_FINISH || cs.action == COMMIT_RECOVER_DELIVER)
  {
    out->redelivery_pending = 1;
    out->pending_sequence = cs.sequence;
    out->pending_offset = cs.range_offset;
    out->pending_length = cs.range_length;
    if (cs.action == COMMIT_RECOVER_FINISH)
    {
      // The key-file/.meta disagreement in this window is exactly the one
      // the artifact's filename tag finishes deterministically on the
      // next operation, so it is reported as consistent rather than as
      // drift - and the committed sequence is the artifact's.
      out->sequence = cs.sequence;
      return 0;
    }
  }

  // The same comparison resync_key_size() makes, reported instead of
  // resolved: smaller-than-declared heals itself on the next operation;
  // larger-than-declared can only mean rolled-back key material, whose
  // leading bytes are already spent - the one fatal state.
  if (physical < (unsigned long long)declared_size)
    out->meta_state = "meta_behind";
  else if (physical > (unsigned long long)declared_size)
    out->meta_state = "rolled_back";
  return 0;
}

static void status_print_direction(const char *contact_name, int is_encrypt,
                                   const DirStatus *d, int porcelain)
{
  const char *p = is_encrypt ? "enc" : "dec";
  if (porcelain)
  {
    printf("%s_sequence=%zu\n", p, d->sequence);
    printf("%s_key_remaining=%llu\n", p, d->key_remaining);
    printf("%s_meta_state=%s\n", p, d->meta_state);
    printf("%s_redelivery_pending=%d\n", p, d->redelivery_pending);
    printf("%s_ack_outstanding=%d\n", p, d->ack_outstanding);
    return;
  }

  printf("  %s:\n", is_encrypt ? "Sending (encrypt)" : "Receiving (decrypt)");
  printf("    Messages %s: %zu\n", is_encrypt ? "sent" : "received", d->sequence);
  printf("    Key remaining: %llu bytes\n", d->key_remaining);
  if (strcmp(d->meta_state, "consistent") == 0)
    printf("    Metadata: consistent with the key file\n");
  else if (strcmp(d->meta_state, "meta_behind") == 0)
    printf("    Metadata: behind the key file (self-heals on the next operation)\n");
  else
    printf("    Metadata: KEY MATERIAL ROLLED BACK - the key file is larger than the "
           "metadata records, so its leading bytes were already spent once. Re-key "
           "this contact before %s anything.\n",
           is_encrypt ? "sending" : "receiving");
  if (d->redelivery_pending)
    printf("    Crash recovery: the next --%s will REDELIVER message #%zu "
           "(key range %zu-%zu) and will NOT process its own input\n",
           is_encrypt ? "encrypt" : "decrypt", d->pending_sequence,
           d->pending_offset, d->pending_offset + d->pending_length);
  else
    printf("    Crash recovery: nothing pending\n");
  if (d->ack_outstanding)
    printf("    Last %s message: awaiting delivery confirmation\n"
           "      (exact %s kept at '%s'; stream it with: otp --recover-last %s %s)\n",
           is_encrypt ? "sent" : "received",
           is_encrypt ? "ciphertext" : "plaintext",
           d->copy_path, contact_name,
           is_encrypt ? "--sent" : "--received");
  else if (d->sequence == 0)
    printf("    Last %s message: none yet\n", is_encrypt ? "sent" : "received");
  else
    printf("    Last %s message: delivery confirmed\n", is_encrypt ? "sent" : "received");
}

int keychain_status(const char *contact_name, int porcelain)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Same lock-then-reload discipline as encrypt/decrypt, so the snapshot
  // is of committed state, never of a moment inside another process's
  // operation. Held only while reading; released before printing.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, contact_name) != 0)
    return -1;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }
  c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    contact_lock_release(&lock);
    return -1;
  }

  DirStatus enc, dec;
  int rc = status_direction(keychain_dir, c, 1, &enc);
  if (rc == 0)
    rc = status_direction(keychain_dir, c, 0, &dec);
  contact_lock_release(&lock);
  if (rc != 0)
    return -1;

  if (porcelain)
  {
    printf("contact=%s\n", c->Name);
    status_print_direction(c->Name, 1, &enc, 1);
    status_print_direction(c->Name, 0, &dec, 1);
  }
  else
  {
    printf("\nContact: %s\n", c->Name);
    status_print_direction(c->Name, 1, &enc, 0);
    status_print_direction(c->Name, 0, &dec, 0);
    printf("\n");
  }

  // One exit code for the most actionable condition across both
  // directions, most severe first: a rollback must be re-keyed before
  // anything else matters; a pending redelivery changes what the next
  // operation's output IS; an outstanding confirmation only gates it.
  if (strcmp(enc.meta_state, "rolled_back") == 0 || strcmp(dec.meta_state, "rolled_back") == 0)
    return KEYCHAIN_STATUS_ROLLED_BACK;
  if (enc.redelivery_pending || dec.redelivery_pending)
    return KEYCHAIN_STATUS_REDELIVERY_PENDING;
  if (enc.ack_outstanding || dec.ack_outstanding)
    return KEYCHAIN_STATUS_ACK_OUTSTANDING;
  return KEYCHAIN_STATUS_CLEAN;
}

int keychain_recover_last(const char *contact_name, int sent, FILE *output)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // The lock is held across the stream so a concurrent operation cannot
  // confirm delivery and remove the copy while it is being read.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, contact_name) != 0)
    return -1;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }
  if (!find_contact(contact_name))
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    contact_lock_release(&lock);
    return -1;
  }

  char src[600];
  last_copy_path(keychain_dir, contact_name, sent, src, sizeof(src));

  unsigned long long src_size;
  if (otp_file_size(src, &src_size) != 0)
  {
    fprintf(stderr,
            "No kept copy of the last %s for contact '%s' - nothing awaits "
            "delivery confirmation in that direction.\n",
            sent ? "sent ciphertext" : "received plaintext", contact_name);
    contact_lock_release(&lock);
    return KEYCHAIN_RECOVER_NO_COPY;
  }

  // deliver_pending_file streams and flush-checks but never deletes -
  // exactly the semantics recovery needs: the copy must outlive every
  // step whose success this process cannot verify, and only the next
  // confirmed operation in this direction may remove it.
  int rc = deliver_pending_file(src, output);
  contact_lock_release(&lock);
  if (rc != 0)
    return -1;

  fprintf(stderr,
          "Recovered %llu bytes of the last %s for contact '%s'. The copy stays at "
          "'%s' until a later operation confirms delivery.\n",
          src_size, sent ? "sent ciphertext" : "received plaintext",
          contact_name, src);
  return 0;
}
