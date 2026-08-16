/*****************************************************************************\
 *                                                                           *
 *   commit.c - Crash-safe, atomically-committed key consumption for OTP     *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "commit.h"
#include "platform.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#define O_BINARY_FLAG _O_BINARY
#define fsync _commit
#define unlink _unlink
#ifndef _MSC_VER
/* Map the POSIX spellings this file uses onto the CRT's underscore names.
 * MSVC also exposes the POSIX names by default, but only as deprecated
 * aliases, so spell the mapping out rather than depending on that - the
 * same mapping keychain.c already makes. */
#define fileno _fileno
#define open _open
#define close _close
#define fdopen _fdopen
#endif
#else
#include <unistd.h>
#define O_BINARY_FLAG 0
#endif

#define READBACK_CHUNK 65536

/* ---- CRC32 (standard reflected, polynomial 0xEDB88320) ---------------- */

static unsigned long crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void)
{
  if (crc32_table_ready)
    return;
  for (unsigned long n = 0; n < 256; n++)
  {
    unsigned long c = n;
    for (int k = 0; k < 8; k++)
      c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
    crc32_table[n] = c;
  }
  crc32_table_ready = 1;
}

static unsigned long crc32_begin(void)
{
  crc32_init_table();
  return 0xFFFFFFFFUL;
}

static unsigned long crc32_feed(unsigned long state, const unsigned char *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    state = crc32_table[(state ^ buf[i]) & 0xFF] ^ (state >> 8);
  return state;
}

static unsigned long crc32_final(unsigned long state)
{
  return state ^ 0xFFFFFFFFUL;
}

/* ---- small helpers ------------------------------------------------------ */

#ifndef _WIN32
static void split_dir(const char *path, char *dir, size_t dir_size)
{
  const char *slash = strrchr(path, '/');
#ifdef _WIN32
  const char *bslash = strrchr(path, '\\');
  if (!slash || (bslash && bslash > slash))
    slash = bslash;
#endif
  if (slash)
  {
    size_t len = (size_t)(slash - path);
    if (len >= dir_size)
      len = dir_size - 1;
    memcpy(dir, path, len);
    dir[len] = '\0';
  }
  else
  {
    snprintf(dir, dir_size, ".");
  }
}
#endif /* !_WIN32 - only fsync_parent_dir's POSIX body uses this */

/* Best-effort: fsync the directory containing `path` so a completed
 * rename() survives a power loss, not just a process kill. Windows has no
 * equivalent (directories aren't opened as file descriptors there), so
 * this is a no-op there. */
static void fsync_parent_dir(const char *path)
{
#ifndef _WIN32
  char dir[600];
  split_dir(path, dir, sizeof(dir));
  int dfd = open(dir, O_RDONLY);
  if (dfd >= 0)
  {
    fsync(dfd);
    close(dfd);
  }
#else
  (void)path;
#endif
}

/* ---- one-shot verified buffer write ------------------------------------ */

int commit_write_verified(const char *tmp_path, const unsigned char *data, size_t size)
{
  unlink(tmp_path);
  int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create %s: %s\n", tmp_path, strerror(errno));
    return -1;
  }
  FILE *f = fdopen(fd, "wb");
  if (!f)
  {
    fprintf(stderr, "Error: fdopen failed for %s: %s\n", tmp_path, strerror(errno));
    close(fd);
    unlink(tmp_path);
    return -1;
  }
  if (size > 0 && fwrite(data, 1, size, f) != size)
  {
    fprintf(stderr, "Error: failed writing %s: %s\n", tmp_path, strerror(errno));
    fclose(f);
    unlink(tmp_path);
    return -1;
  }
  if (fflush(f) != 0 || fsync(fileno(f)) != 0)
  {
    fprintf(stderr, "Error: failed to fsync %s: %s\n", tmp_path, strerror(errno));
    fclose(f);
    unlink(tmp_path);
    return -1;
  }
  fclose(f);

  commit_test_corrupt_file("verified_write", tmp_path);

  /* Read back and verify byte-for-byte against what we intended to write -
   * a successful fwrite() only proves libc accepted the bytes, not that
   * they are durably and correctly present on disk. */
  FILE *rf = fopen(tmp_path, "rb");
  if (!rf)
  {
    fprintf(stderr, "Error: cannot reopen %s for verification: %s\n", tmp_path, strerror(errno));
    unlink(tmp_path);
    return -1;
  }
  unsigned char buf[READBACK_CHUNK];
  size_t compared = 0;
  int mismatch = 0;
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), rf)) > 0)
  {
    if (compared + n > size || memcmp(buf, data + compared, n) != 0)
    {
      mismatch = 1;
      break;
    }
    compared += n;
  }
  int had_error = ferror(rf);
  fclose(rf);
  if (mismatch || had_error || compared != size)
  {
    fprintf(stderr, "Error: verification failed for %s (read-back does not match what was written)\n", tmp_path);
    unlink(tmp_path);
    return -1;
  }
  return 0;
}

/* ---- streaming verified write ------------------------------------------ */

int commit_stage_open(CommitStage *stage, const char *tmp_path)
{
  memset(stage, 0, sizeof(*stage));
  unlink(tmp_path);
  int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create staging file %s: %s\n", tmp_path, strerror(errno));
    return -1;
  }
  stage->f = fdopen(fd, "wb");
  if (!stage->f)
  {
    fprintf(stderr, "Error: fdopen failed for %s: %s\n", tmp_path, strerror(errno));
    close(fd);
    unlink(tmp_path);
    return -1;
  }
  stage->crc = crc32_begin();
  stage->written = 0;
  snprintf(stage->tmp_path, sizeof(stage->tmp_path), "%s", tmp_path);
  return 0;
}

int commit_stage_write(CommitStage *stage, const unsigned char *data, size_t len)
{
  if (len == 0)
    return 0;
  if (fwrite(data, 1, len, stage->f) != len)
  {
    fprintf(stderr, "Error: failed writing to staging file %s: %s\n", stage->tmp_path, strerror(errno));
    return -1;
  }
  stage->crc = crc32_feed(stage->crc, data, len);
  stage->written += len;
  return 0;
}

int commit_stage_close_verified(CommitStage *stage)
{
  if (fflush(stage->f) != 0 || fsync(fileno(stage->f)) != 0)
  {
    fprintf(stderr, "Error: failed to fsync staging file %s: %s\n", stage->tmp_path, strerror(errno));
    fclose(stage->f);
    stage->f = NULL;
    unlink(stage->tmp_path);
    return -1;
  }
  fclose(stage->f);
  stage->f = NULL;

  commit_test_corrupt_file("staged_output", stage->tmp_path);

  FILE *rf = fopen(stage->tmp_path, "rb");
  if (!rf)
  {
    fprintf(stderr, "Error: cannot reopen staging file %s for verification: %s\n", stage->tmp_path, strerror(errno));
    unlink(stage->tmp_path);
    return -1;
  }
  unsigned char buf[READBACK_CHUNK];
  unsigned long check_crc = crc32_begin();
  size_t total = 0, n;
  while ((n = fread(buf, 1, sizeof(buf), rf)) > 0)
  {
    check_crc = crc32_feed(check_crc, buf, n);
    total += n;
  }
  int had_error = ferror(rf);
  fclose(rf);
  if (had_error || total != stage->written || crc32_final(check_crc) != crc32_final(stage->crc))
  {
    fprintf(stderr, "Error: verification failed for staged file %s (read-back does not match what was written)\n", stage->tmp_path);
    unlink(stage->tmp_path);
    return -1;
  }
  return 0;
}

void commit_stage_abort(CommitStage *stage)
{
  if (stage->f)
  {
    fclose(stage->f);
    stage->f = NULL;
  }
  if (stage->tmp_path[0])
    unlink(stage->tmp_path);
}

/* ---- publish / discard -------------------------------------------------- */

int commit_publish(const char *tmp_path, const char *final_path)
{
  /* otp_rename_replace(), not rename(): every publish here lands on a path
   * that already exists, and the Windows CRT rename() refuses that. See
   * platform.h. */
  if (otp_rename_replace(tmp_path, final_path) != 0)
  {
    fprintf(stderr, "Error: failed to publish %s -> %s: %s\n", tmp_path, final_path, strerror(errno));
    return -1;
  }
  fsync_parent_dir(final_path);
  return 0;
}

void commit_discard_path(const char *path)
{
  unlink(path);
}

/* ---- pending output artifacts ------------------------------------------ */

void commit_pending_path(const char *keychain_dir, const char *contact,
                          const char *direction, size_t sequence,
                          size_t offset, size_t length,
                          char *out, size_t out_size)
{
  snprintf(out, out_size, "%s/%s_%s_pending_seq%zu_off%zu_len%zu.bin",
           keychain_dir, contact, direction, sequence, offset, length);
}

static int parse_pending_name(const char *name, const char *prefix,
                               size_t *seq, size_t *off, size_t *len)
{
  size_t prefix_len = strlen(prefix);
  if (strncmp(name, prefix, prefix_len) != 0)
    return 0;
  return sscanf(name + prefix_len, "%zu_off%zu_len%zu.bin", seq, off, len) == 3;
}

static int has_suffix(const char *name, const char *suffix)
{
  size_t n = strlen(name), s = strlen(suffix);
  return n >= s && strcmp(name + n - s, suffix) == 0;
}

/* Build the two name fragments that identify everything one direction of
 * one contact can leave behind in the keychain directory:
 *   <contact>_<dir>_pending_seq<N>_off<O>_len<L>.bin - a published,
 *     fully-verified artifact; the input to the recovery truth table.
 *   <contact>_<dir>_pending.<pid>.tmp - a *staging* file, still being
 *     written when its process died. It was never verified and never
 *     published, so it carries no recoverable meaning - but it does hold
 *     real message content (on the decrypt side, recovered plaintext),
 *     so it must not be left lying around. Callers sweep these while
 *     holding the contact lock, which is what makes deleting them safe:
 *     no other process can be mid-staging for this contact+direction.
 */
static void build_pending_prefixes(const char *contact, const char *direction,
                                    char *artifact_prefix, size_t artifact_size,
                                    char *stage_prefix, size_t stage_size)
{
  snprintf(artifact_prefix, artifact_size, "%s_%s_pending_seq", contact, direction);
  snprintf(stage_prefix, stage_size, "%s_%s_pending.", contact, direction);
}

int commit_reconcile(const char *keychain_dir, const char *contact,
                      const char *direction, const char *key_file_path,
                      size_t declared_offset, size_t declared_size,
                      size_t declared_sequence, CommitRecovery *out)
{
  (void)declared_sequence;
  memset(out, 0, sizeof(*out));
  out->action = COMMIT_RECOVER_NONE;

  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; /* no keychain dir yet - nothing to reconcile */

  char prefix[300], stage_prefix[300];
  build_pending_prefixes(contact, direction, prefix, sizeof(prefix),
                         stage_prefix, sizeof(stage_prefix));

  struct dirent *entry;
  char found_path[600] = {0};
  size_t found_seq = 0, found_offset = 0, found_len = 0;
  int found = 0;

  while ((entry = readdir(d)) != NULL)
  {
    size_t seq, off, len;

    /* Sweep abandoned staging files first. These are never recoverable -
     * an unfinished, unverified write - but they can be large and, when
     * left by an interrupted decrypt, they contain plaintext. */
    if (strncmp(entry->d_name, stage_prefix, strlen(stage_prefix)) == 0 &&
        has_suffix(entry->d_name, ".tmp"))
    {
      char stale_path[600];
      snprintf(stale_path, sizeof(stale_path), "%s/%s", keychain_dir, entry->d_name);
      unlink(stale_path);
      continue;
    }

    if (!parse_pending_name(entry->d_name, prefix, &seq, &off, &len))
      continue;

    char full_path[600];
    snprintf(full_path, sizeof(full_path), "%s/%s", keychain_dir, entry->d_name);

    if (found)
    {
      /* Should never happen given reconcile always runs before any new
       * operation starts - defensively discard rather than guess. */
      fprintf(stderr, "Warning: discarding unexpected extra pending artifact %s\n", full_path);
      unlink(full_path);
      continue;
    }

    snprintf(found_path, sizeof(found_path), "%s", full_path);
    found_seq = seq;
    found_offset = off;
    found_len = len;
    found = 1;
  }
  closedir(d);

  if (!found)
    return 0;

  unsigned long long key_size_64;
  if (otp_file_size(key_file_path, &key_size_64) != 0)
  {
    fprintf(stderr, "Warning: cannot stat key file %s while reconciling %s: %s\n",
            key_file_path, found_path, strerror(errno));
    unlink(found_path);
    out->action = COMMIT_RECOVER_ERROR;
    return -1;
  }
  size_t actual_key_size = (size_t)key_size_64;

  out->sequence = found_seq;
  out->range_offset = found_offset;
  out->range_length = found_len;
  snprintf(out->pending_path, sizeof(out->pending_path), "%s", found_path);

  if (actual_key_size == declared_size && declared_offset == found_offset)
  {
    /* Window 1: neither the key file nor the .meta file reflect this
     * operation - it never committed. Nothing was ever spent or
     * delivered, so the leftover artifact is simply stale. */
    unlink(found_path);
    out->action = COMMIT_RECOVER_DISCARD;
    return 0;
  }

  if (actual_key_size + found_len == declared_size && declared_offset == found_offset)
  {
    /* Window 2: the key file was already truncated for this operation,
     * but the .meta file hasn't caught up. Finish the commit using the
     * values recorded in the artifact's own filename - no guessing. */
    out->action = COMMIT_RECOVER_FINISH;
    out->corrected_offset = found_offset + found_len;
    out->corrected_size = actual_key_size;
    return 0;
  }

  if (actual_key_size == declared_size && declared_offset == found_offset + found_len)
  {
    /* Window 3: fully committed already - only delivery/cleanup remains. */
    out->action = COMMIT_RECOVER_DELIVER;
    return 0;
  }

  fprintf(stderr,
          "Warning: pending artifact %s does not match a recognized recovery state "
          "(declared offset=%zu size=%zu, actual key size=%zu) - discarding without redelivery\n",
          found_path, declared_offset, declared_size, actual_key_size);
  unlink(found_path);
  out->action = COMMIT_RECOVER_ERROR;
  return 0;
}

void commit_discard_all_pending(const char *keychain_dir, const char *contact)
{
  DIR *d = opendir(keychain_dir);
  if (!d)
    return;

  /* Match on the shared "<contact>_<dir>_pending" stem so this covers
   * both published artifacts and abandoned staging files
   * (<contact>_<dir>_pending.<pid>.tmp). This is the only thing that ever
   * revisits a dead process's pid-tagged name, so anything it misses
   * stays on disk forever - and on the decrypt side that file holds
   * recovered plaintext. */
  char prefix_enc[300], prefix_dec[300];
  snprintf(prefix_enc, sizeof(prefix_enc), "%s_enc_pending", contact);
  snprintf(prefix_dec, sizeof(prefix_dec), "%s_dec_pending", contact);

  struct dirent *entry;
  while ((entry = readdir(d)) != NULL)
  {
    if (strncmp(entry->d_name, prefix_enc, strlen(prefix_enc)) == 0 ||
        strncmp(entry->d_name, prefix_dec, strlen(prefix_dec)) == 0)
    {
      char full_path[600];
      snprintf(full_path, sizeof(full_path), "%s/%s", keychain_dir, entry->d_name);
      unlink(full_path);
    }
  }
  closedir(d);
}

/* ---- per-contact mutual exclusion --------------------------------------- */

int contact_lock_acquire(ContactLock *lock, const char *keychain_dir, const char *contact)
{
  lock->fd = -1;
  snprintf(lock->path, sizeof(lock->path), "%s/%s.lock", keychain_dir, contact);

  int fd = open(lock->path, O_CREAT | O_RDWR | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create lock file %s: %s\n", lock->path, strerror(errno));
    return -1;
  }

  /* Blocks until any other process holding this contact's lock releases
   * it - including via crash or kill, since the OS drops the lock as
   * soon as the holding file descriptor closes (POSIX flock() and the
   * Windows LockFileEx-backed shim in platform.h both guarantee this). */
  if (flock(fd, LOCK_EX) != 0)
  {
    fprintf(stderr, "Error: failed to lock %s: %s\n", lock->path, strerror(errno));
    close(fd);
    return -1;
  }

  lock->fd = fd;
  return 0;
}

void contact_lock_release(ContactLock *lock)
{
  if (lock->fd >= 0)
  {
    flock(lock->fd, LOCK_UN);
    close(lock->fd);
    lock->fd = -1;
  }
}

/* ---- test-only fault injection ------------------------------------------ */

void commit_test_corrupt_file(const char *point, const char *path)
{
  const char *target = getenv("OTP_TEST_CORRUPT_POINT");
  if (!target || strcmp(target, point) != 0)
    return;

  FILE *f = fopen(path, "r+b");
  if (!f)
    return;
  int first = fgetc(f);
  if (first == EOF)
  {
    /* Empty payload: make it non-empty so the length check catches it. */
    fclose(f);
    f = fopen(path, "ab");
    if (f)
    {
      fputc('X', f);
      fclose(f);
    }
    return;
  }
  if (fseek(f, 0, SEEK_SET) == 0)
    fputc(first ^ 0xFF, f);
  fclose(f);
}

void commit_test_crash_point(const char *point)
{
  const char *target = getenv("OTP_TEST_CRASH_POINT");
  if (target && strcmp(target, point) == 0)
  {
    fflush(NULL);
    _Exit(77);
  }
}
