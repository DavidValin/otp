/*****************************************************************************\
 *                                                                           *
 *   keychain.c - Keychain management for OTP contacts                       *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "keychain.h"
#include "commit.h"
#include "platform.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

// Platform-specific includes
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
// Windows compatibility mappings
#define mkdir(path, mode) _mkdir(path)
#define unlink(path) _unlink(path)
#define stat _stat
/* MinGW's <sys/stat.h> already defines these; MSVC's does not */
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#define getpid _getpid
#define O_BINARY_FLAG _O_BINARY
#ifndef _MSC_VER
#define fileno _fileno
#define open _open
#define close _close
#define fdopen _fdopen
#endif
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
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

// Global keychain instance
Keychain g_keychain = {0};

// The keychain is a single directory, resolved relative to the process's
// current working directory. That is the whole location scheme: there is
// no keychain index file, and no path is derived from one. Running otp
// from a different directory therefore uses a different keychain, which
// is what lets two correspondents' keychains sit side by side.
#define KEYCHAIN_DIR_NAME ".keychain"

// Get keychain directory path (creates if doesn't exist)
static int get_keychain_dir(char *dir_path, size_t dir_path_size)
{
  if (snprintf(dir_path, dir_path_size, "%s", KEYCHAIN_DIR_NAME) >= (int)dir_path_size)
    return -1;

  // Create directory if it doesn't exist
  struct stat st = {0};
  if (stat(dir_path, &st) == -1)
  {
    if (mkdir(dir_path, 0700) != 0)
    {
      fprintf(stderr, "Error: Failed to create keychain directory '%s': %s\n",
              dir_path, strerror(errno));
      return -1;
    }
  }
  return 0;
}

// Copy a key file into the keychain directory, streaming so that a
// terabyte-scale key is never held in RAM.
//
// The destination is *created* with mode 0600 rather than created under
// the process umask (which typically yields 0644) and tightened
// afterwards: one-time-pad key material is the entire secret here, and
// creating it readable leaves a window - however brief - in which any
// other local user can copy it. The copy is fsynced before it is
// considered done, so a crash immediately after adding a contact cannot
// leave a short key file behind metadata that claims the full length.
static int copy_key_file(const char *src_path, const char *dst_path)
{
  FILE *src = fopen(src_path, "rb");
  if (!src)
  {
    fprintf(stderr, "Error: Cannot open key file '%s': %s\n", src_path, strerror(errno));
    return -1;
  }

  int fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: Cannot create key file '%s': %s\n", dst_path, strerror(errno));
    fclose(src);
    return -1;
  }
  FILE *dst = fdopen(fd, "wb");
  if (!dst)
  {
    fprintf(stderr, "Error: Cannot write key file '%s': %s\n", dst_path, strerror(errno));
    close(fd);
    unlink(dst_path);
    fclose(src);
    return -1;
  }

  unsigned char buffer[1024 * 1024]; // 1MB streaming buffer
  size_t bytes;
  while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
  {
    if (fwrite(buffer, 1, bytes, dst) != bytes)
    {
      fprintf(stderr, "Error: Failed to write key file '%s': %s\n", dst_path, strerror(errno));
      fclose(dst);
      fclose(src);
      unlink(dst_path);
      return -1;
    }
  }

  int read_failed = ferror(src);
  fclose(src);

  if (read_failed || fflush(dst) != 0 || otp_fsync(fileno(dst)) != 0)
  {
    fprintf(stderr, "Error: Failed to store key file '%s': %s\n", dst_path, strerror(errno));
    fclose(dst);
    unlink(dst_path);
    return -1;
  }
  fclose(dst);
  return 0;
}

// Two key files holding the same bytes are the same one-time pad. Giving
// a contact that pad for both directions means the range that encrypts an
// outgoing message is the same range that decrypts an incoming one - two
// messages sharing key material, which is precisely the break the pad
// must never suffer. Refusing here is the only point at which this is
// cheaply detectable; afterwards the two copies are independent files and
// nothing distinguishes them from a legitimately distinct pair.
//
// Compared by content rather than by path: a copy (cp k.bin k2.bin) is
// exactly as dangerous as passing the same filename twice, and a path
// comparison would miss it, as would an inode comparison.
//
// Equal size is NOT a precondition for danger, so it is not used as a
// shortcut. Key material here is consumed from the front and the file is
// truncated, so the natural leftover of this tool - a partially consumed
// key from .keychain/ - is a *suffix* of the pad it came from. Handing
// over a pad and its own leftover is overlap just as total as handing
// over the same file twice, and the sizes differ precisely because some
// of it was already spent. A truncated head of a pad is the mirror image
// of that case.
//
// Nor is overlap confined to those two alignments: a pad trimmed at both
// ends, or two windows cut from the same pad, share key material without
// either file being a prefix or suffix of the other. Detection therefore
// searches for each file's opening KEY_ANCHOR_LEN bytes at *every* offset
// of the other file, with a rolling hash so the search is one sequential
// read of each file. Any overlap that includes either file's first
// KEY_ANCHOR_LEN bytes is found this way; only an overlap that excludes
// both files' heads (which no artifact of this tool produces - every
// truncation preserves one end) or one shorter
// than the anchor can escape. Files smaller than the anchor keep the two
// aligned comparisons only: a handful of bytes genuinely can coincide in
// two independent pads, and refusing on such a coincidence would reject
// legitimate keys.
//
// The cost is a full read of both files rather than the early-exit a
// front-only comparison would allow. Adding a contact is rare and this is
// the one moment overlap is detectable at all, so the trade is taken.
#define KEY_COMPARE_CHUNK (1024 * 1024)
#define KEY_ANCHOR_LEN 64

typedef enum
{
  KEY_OVERLAP_NONE = 0,
  KEY_OVERLAP_IDENTICAL, // same size, same bytes
  KEY_OVERLAP_PREFIX,    // the shorter file is the head of the longer
  KEY_OVERLAP_SUFFIX,    // the shorter file is the tail of the longer
  KEY_OVERLAP_INTERIOR,  // shared material at an unaligned, interior offset
  KEY_OVERLAP_UNKNOWN    // comparison could not be carried out at all
} KeyOverlap;

// Polynomial rolling hash over a KEY_ANCHOR_LEN-byte window, modulo 2^64
// via unsigned wraparound. Not cryptographic and does not need to be: a
// collision only costs a byte comparison (or, for the spent-heads
// registry, a second, structurally different digest check).
#define KEY_HASH_BASE 1099511628211ULL

static uint64_t anchor_hash(const unsigned char *buf, size_t len)
{
  uint64_t h = 0;
  for (size_t i = 0; i < len; i++)
    h = h * KEY_HASH_BASE + buf[i];
  return h;
}

// FNV-1a: the independent second digest used to confirm a rolling-hash
// hit where the original bytes are no longer available to compare
// against (the spent-heads registry stores digests, never key bytes).
static uint64_t confirm_hash(const unsigned char *buf, size_t len)
{
  uint64_t h = 14695981039346656037ULL;
  for (size_t i = 0; i < len; i++)
  {
    h ^= buf[i];
    h *= 1099511628211ULL;
  }
  return h;
}

// The weight the oldest byte of the window carries in the rolling hash,
// KEY_HASH_BASE^(KEY_ANCHOR_LEN-1) mod 2^64.
static uint64_t rolling_out_weight(void)
{
  uint64_t w = 1;
  for (int i = 0; i < KEY_ANCHOR_LEN - 1; i++)
    w *= KEY_HASH_BASE;
  return w;
}

// Search `hay_path` (of size `hay_size`) for the first KEY_ANCHOR_LEN
// bytes of `needle_path`. Returns 1 and sets *found_at to the byte offset
// of the first match, 0 when absent, -1 when the search could not be
// carried out - which, exactly like file_ranges_equal()'s -1, must stay
// distinct from "absent": a failed search proves nothing about the files.
static int find_head_in_file(const char *needle_path,
                             const char *hay_path, size_t hay_size,
                             size_t *found_at)
{
  // Same fault injection as file_ranges_equal(): the whole overlap check
  // must fail closed together.
  if (getenv("OTP_TEST_FAIL_KEY_COMPARE"))
    return -1;
  if (hay_size < KEY_ANCHOR_LEN)
    return 0;

  unsigned char anchor[KEY_ANCHOR_LEN];
  FILE *nf = fopen(needle_path, "rb");
  if (!nf)
    return -1;
  size_t got = fread(anchor, 1, KEY_ANCHOR_LEN, nf);
  fclose(nf);
  if (got != KEY_ANCHOR_LEN)
    return -1; // callers only search for heads they know are this long

  uint64_t target = anchor_hash(anchor, KEY_ANCHOR_LEN);
  uint64_t out_weight = rolling_out_weight();

  FILE *hf = fopen(hay_path, "rb");
  unsigned char *buf = malloc(KEY_COMPARE_CHUNK);
  if (!hf || !buf)
  {
    free(buf);
    if (hf)
      fclose(hf);
    return -1;
  }

  // Circular window of the last KEY_ANCHOR_LEN bytes; the byte at
  // absolute position p lives at index p % KEY_ANCHOR_LEN.
  unsigned char window[KEY_ANCHOR_LEN];
  uint64_t h = 0;
  size_t pos = 0;
  int result = 0;

  size_t n;
  while (result == 0 && (n = fread(buf, 1, KEY_COMPARE_CHUNK, hf)) > 0)
  {
    for (size_t i = 0; i < n; i++)
    {
      unsigned char c = buf[i];
      if (pos >= KEY_ANCHOR_LEN)
        h = (h - (uint64_t)window[pos % KEY_ANCHOR_LEN] * out_weight) * KEY_HASH_BASE + c;
      else
        h = h * KEY_HASH_BASE + c;
      window[pos % KEY_ANCHOR_LEN] = c;
      pos++;
      if (pos >= KEY_ANCHOR_LEN && h == target)
      {
        size_t start = pos - KEY_ANCHOR_LEN;
        int match = 1;
        for (int j = 0; j < KEY_ANCHOR_LEN; j++)
        {
          if (window[(start + j) % KEY_ANCHOR_LEN] != anchor[j])
          {
            match = 0;
            break;
          }
        }
        if (match)
        {
          *found_at = start;
          result = 1;
          break;
        }
      }
    }
  }

  // stat said hay_size bytes exist; reading fewer without an error flag
  // still means the file changed underfoot or the read silently failed.
  if (result == 0 && (ferror(hf) || pos != hay_size))
    result = -1;

  free(buf);
  fclose(hf);
  return result;
}

// Compare `length` bytes of two files, each starting at its own offset.
// Returns 1 if every byte matches, 0 if any byte differs, and -1 if the
// comparison could not be carried out (open/allocate/seek/read failure).
// The -1 case must stay distinct from 0: a failure here proves nothing
// about the ranges, and reporting it as "differ" would let two identical
// pads slip through the overlap check. Nor can the copy step that
// follows be trusted to hit the same problem - it uses a stack buffer
// and opens its files sequentially, so neither an allocation failure nor
// fd exhaustion here has to reproduce there.
static int file_ranges_equal(const char *path_a, size_t offset_a,
                             const char *path_b, size_t offset_b,
                             size_t length)
{
  if (length == 0)
    return 0;

  FILE *fa = fopen(path_a, "rb");
  FILE *fb = fopen(path_b, "rb");
  unsigned char *buf_a = malloc(KEY_COMPARE_CHUNK);
  unsigned char *buf_b = malloc(KEY_COMPARE_CHUNK);

  int result = (fa && fb && buf_a && buf_b) ? 1 : -1;

  // Test-only fault injection: simulates the acquisitions above failing,
  // to prove the check fails closed instead of reading as "no overlap".
  // A no-op whenever the variable isn't set.
  if (getenv("OTP_TEST_FAIL_KEY_COMPARE"))
    result = -1;

  // otp_fseek(), not fseek(): fseek() takes a long, which is 32-bit on
  // Windows even in 64-bit builds, so a tail comparison on a key over
  // 2GB would silently start in the wrong place.
  if (result == 1 && (otp_fseek(fa, offset_a) != 0 || otp_fseek(fb, offset_b) != 0))
    result = -1;

  size_t left = length;
  while (result == 1 && left > 0)
  {
    size_t want = (left < KEY_COMPARE_CHUNK) ? left : KEY_COMPARE_CHUNK;
    if (fread(buf_a, 1, want, fa) != want || fread(buf_b, 1, want, fb) != want)
      result = -1; // stat said these bytes exist, so a short read is an I/O failure
    else if (memcmp(buf_a, buf_b, want) != 0)
      result = 0;
    else
      left -= want;
  }

  free(buf_a);
  free(buf_b);
  if (fa)
    fclose(fa);
  if (fb)
    fclose(fb);
  return result;
}

static KeyOverlap key_files_overlap(const char *path_a, const char *path_b,
                                    size_t size_a, size_t size_b)
{
  size_t shorter = (size_a < size_b) ? size_a : size_b;
  if (shorter == 0)
    return KEY_OVERLAP_NONE;

  // Files smaller than one anchor: aligned comparisons only (see the
  // block comment above KEY_COMPARE_CHUNK for why an interior search on
  // so few bytes would produce false refusals).
  if (shorter < KEY_ANCHOR_LEN)
  {
    int front = file_ranges_equal(path_a, 0, path_b, 0, shorter);
    if (front < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (front)
      return (size_a == size_b) ? KEY_OVERLAP_IDENTICAL : KEY_OVERLAP_PREFIX;
    if (size_a == size_b)
      return KEY_OVERLAP_NONE;
    int tail = file_ranges_equal(path_a, size_a - shorter, path_b, size_b - shorter, shorter);
    if (tail < 0)
      return KEY_OVERLAP_UNKNOWN;
    return tail ? KEY_OVERLAP_SUFFIX : KEY_OVERLAP_NONE;
  }

  // Search for each file's opening anchor anywhere in the other. This
  // covers the aligned cases (a prefix match sits at offset 0, a suffix
  // match at the end) and every interior or partially-shifted overlap
  // that includes either file's head.
  for (int swapped = 0; swapped < 2; swapped++)
  {
    const char *needle = swapped ? path_b : path_a;
    const char *hay = swapped ? path_a : path_b;
    size_t needle_size = swapped ? size_b : size_a;
    size_t hay_size = swapped ? size_a : size_b;

    size_t at = 0;
    int found = find_head_in_file(needle, hay, hay_size, &at);
    if (found < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (!found)
      continue;

    // The anchor match alone is already KEY_ANCHOR_LEN bytes of shared
    // pad. The full-extent comparison below only refines *how* the files
    // overlap for the caller's message; if the bytes past the anchor
    // diverge the pair still shares key material and is still refused,
    // just reported as interior overlap.
    size_t extent = hay_size - at;
    if (extent > needle_size)
      extent = needle_size;
    int whole = file_ranges_equal(needle, 0, hay, at, extent);
    if (whole < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (whole != 1)
      return KEY_OVERLAP_INTERIOR;
    if (at == 0)
      return (size_a == size_b) ? KEY_OVERLAP_IDENTICAL : KEY_OVERLAP_PREFIX;
    if (at + needle_size == hay_size)
      return KEY_OVERLAP_SUFFIX;
    return KEY_OVERLAP_INTERIOR;
  }

  return KEY_OVERLAP_NONE;
}

// ---------------------------------------------------------------------------
// The spent-heads registry: <keychain_dir>/spent_heads
//
// Removing a contact deletes its key files, so nothing remains for the
// overlap check above to compare a later candidate against - which is
// exactly how a partially spent ORIGINAL key file could come back under a
// brand-new contact name and restart at offset 0 over bytes that already
// encrypted messages. The registry closes that hole: the first time a
// key's opening bytes are about to be consumed, two 64-bit digests of its
// first KEY_ANCHOR_LEN bytes are appended here, and every future add
// scans its candidate files for any registered head at any offset. The
// original always contains its own spent head, so it is recognized no
// matter what the contact is now called; the legitimately reusable
// remainder no longer contains it, so it still passes.
//
// Only digests are stored, never key bytes. This is still a deliberate,
// documented trade-off rather than a free lunch: a digest of spent pad
// bytes is a confirmation oracle - someone who reads this file AND holds
// a captured ciphertext can *verify a complete guess* of that message's
// first KEY_ANCHOR_LEN plaintext bytes. It recovers nothing by itself,
// and anyone able to read .keychain/ already holds every live key in it,
// which is strictly worse. The alternative - no durable trace - is the
// silent two-time pad this registry exists to prevent.
//
// Entries are one line each, "v1 <enc|dec> <rolling-hash> <confirm-hash>",
// appended and fsynced. The direction matters when a match is judged: a
// candidate DECRYPTION key containing an ENC-spent head is the mirrored
// other-endpoint pattern (it will decrypt exactly the messages those
// bytes already encrypted) and is only warned about; every other pairing
// means the same pad would cover two different messages and is refused.
// ---------------------------------------------------------------------------

typedef struct
{
  char direction[4]; // "enc" or "dec"
  uint64_t roll;
  uint64_t confirm;
} SpentHead;

static void spent_heads_path(const char *keychain_dir, char *path, size_t path_size)
{
  snprintf(path, path_size, "%s%cspent_heads", keychain_dir, PATH_SEPARATOR);
}

// Load every well-formed entry. A missing file is an empty registry. A
// malformed line (a torn append from a crash) is skipped rather than
// fatal: the entry it would have held was never durably recorded, and
// treating it as fatal would refuse every future add forever.
static int spent_heads_load(const char *keychain_dir, SpentHead **out, size_t *count)
{
  *out = NULL;
  *count = 0;

  char path[600];
  spent_heads_path(keychain_dir, path, sizeof(path));
  FILE *f = fopen(path, "r");
  if (!f)
    return (errno == ENOENT) ? 0 : -1;

  SpentHead *heads = NULL;
  size_t n = 0, cap = 0;
  char line[128];
  while (fgets(line, sizeof(line), f))
  {
    SpentHead h;
    unsigned long long roll, confirm;
    if (sscanf(line, "v1 %3s %llx %llx", h.direction, &roll, &confirm) != 3 ||
        (strcmp(h.direction, "enc") != 0 && strcmp(h.direction, "dec") != 0))
      continue;
    h.roll = roll;
    h.confirm = confirm;
    if (n == cap)
    {
      size_t new_cap = cap ? cap * 2 : 16;
      SpentHead *nh = realloc(heads, new_cap * sizeof(*nh));
      if (!nh)
      {
        free(heads);
        fclose(f);
        return -1;
      }
      heads = nh;
      cap = new_cap;
    }
    heads[n++] = h;
  }

  int bad = ferror(f);
  fclose(f);
  if (bad)
  {
    free(heads);
    return -1;
  }
  *out = heads;
  *count = n;
  return 0;
}

// Record the head of `key_path` as spent. Called at the moment the key's
// first bytes are about to be consumed for the first time, BEFORE any
// consumption is committed: recorded-but-unspent (after a crash) costs at
// worst a spurious refusal of a key that was never actually used, while
// spent-but-unrecorded would silently lose the very protection the
// registry provides. A failure here must therefore abort the caller's
// operation while nothing has been spent yet.
static int spent_head_record(const char *keychain_dir, const char *direction,
                             const char *key_path)
{
  // Test-only fault injection: proves a failed record aborts the
  // operation before key material is spent. A no-op when unset.
  if (getenv("OTP_TEST_FAIL_SPENT_RECORD"))
    return -1;

  unsigned char head[KEY_ANCHOR_LEN];
  FILE *kf = fopen(key_path, "rb");
  if (!kf)
    return -1;
  size_t got = fread(head, 1, KEY_ANCHOR_LEN, kf);
  fclose(kf);
  // A key with fewer than KEY_ANCHOR_LEN bytes cannot be recorded (or
  // later searched for) without false positives; what a missed record
  // leaves unprotected is smaller than one anchor.
  if (got < KEY_ANCHOR_LEN)
    return 0;

  uint64_t roll = anchor_hash(head, KEY_ANCHOR_LEN);
  uint64_t confirm = confirm_hash(head, KEY_ANCHOR_LEN);

  // Skip an entry that is already present: crash recovery can pass
  // through offset 0 more than once for the same head.
  SpentHead *heads = NULL;
  size_t n = 0;
  if (spent_heads_load(keychain_dir, &heads, &n) != 0)
    return -1;
  for (size_t i = 0; i < n; i++)
  {
    if (heads[i].roll == roll && heads[i].confirm == confirm &&
        strcmp(heads[i].direction, direction) == 0)
    {
      free(heads);
      return 0;
    }
  }
  free(heads);

  char path[600];
  spent_heads_path(keychain_dir, path, sizeof(path));
  // O_APPEND with a single sub-buffer-sized write, so two processes
  // spending different contacts' keys at once interleave whole lines,
  // never fragments. Created 0600 like everything else in .keychain.
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY_FLAG, 0600);
  if (fd < 0)
    return -1;
  FILE *f = fdopen(fd, "ab");
  if (!f)
  {
    close(fd);
    return -1;
  }
  int rc = 0;
  if (fprintf(f, "v1 %s %016llx %016llx\n", direction,
              (unsigned long long)roll, (unsigned long long)confirm) < 0 ||
      fflush(f) != 0 || otp_fsync(fileno(f)) != 0)
    rc = -1;
  if (fclose(f) != 0)
    rc = -1;
  return rc;
}

// Scan `path` for any registered spent head at any byte offset, with the
// same rolling hash the pairwise search uses. Returns 1 and the matching
// entry's index, 0 when clean, and -1 when the scan could not be carried
// out - which callers must treat as "not proven clean", never as clean.
static int spent_heads_scan_file(const char *path, const SpentHead *heads,
                                 size_t count, size_t *match)
{
  if (count == 0)
    return 0;

  FILE *f = fopen(path, "rb");
  unsigned char *buf = malloc(KEY_COMPARE_CHUNK);
  if (!f || !buf)
  {
    free(buf);
    if (f)
      fclose(f);
    return -1;
  }

  uint64_t out_weight = rolling_out_weight();
  unsigned char window[KEY_ANCHOR_LEN];
  uint64_t h = 0;
  size_t pos = 0;
  int result = 0;

  size_t n;
  while (result == 0 && (n = fread(buf, 1, KEY_COMPARE_CHUNK, f)) > 0)
  {
    for (size_t i = 0; i < n && result == 0; i++)
    {
      unsigned char c = buf[i];
      if (pos >= KEY_ANCHOR_LEN)
        h = (h - (uint64_t)window[pos % KEY_ANCHOR_LEN] * out_weight) * KEY_HASH_BASE + c;
      else
        h = h * KEY_HASH_BASE + c;
      window[pos % KEY_ANCHOR_LEN] = c;
      pos++;
      if (pos < KEY_ANCHOR_LEN)
        continue;

      // The confirm digest is computed at most once per position, and
      // only when some entry's rolling hash already matched.
      uint64_t confirm = 0;
      int have_confirm = 0;
      for (size_t e = 0; e < count; e++)
      {
        if (heads[e].roll != h)
          continue;
        if (!have_confirm)
        {
          unsigned char ordered[KEY_ANCHOR_LEN];
          size_t start = pos - KEY_ANCHOR_LEN;
          for (int j = 0; j < KEY_ANCHOR_LEN; j++)
            ordered[j] = window[(start + j) % KEY_ANCHOR_LEN];
          confirm = confirm_hash(ordered, KEY_ANCHOR_LEN);
          have_confirm = 1;
        }
        if (heads[e].confirm == confirm)
        {
          *match = e;
          result = 1;
          break;
        }
      }
    }
  }

  if (result == 0 && ferror(f))
    result = -1;

  free(buf);
  fclose(f);
  return result;
}

// A contact name that has been used before is a reuse hazard the program
// cannot see through: its key files are gone, so there is nothing left to
// compare a freshly supplied key against. The lock file deliberately
// outlives a removed contact, which makes it the one durable trace that
// this name was in service. Warn rather than refuse - rotating a contact
// onto genuinely fresh keys is legitimate and common - but say plainly
// which key files are safe to supply.
static void warn_if_name_previously_used(const char *keychain_dir, const char *name)
{
  char path[600];
  unsigned long long ignored;
  int had_keys = 0, had_lock = 0;

  snprintf(path, sizeof(path), "%s%c%s_enc.key", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_keys = 1;
  snprintf(path, sizeof(path), "%s%c%s_dec.key", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_keys = 1;
  snprintf(path, sizeof(path), "%s%c%s.lock", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_lock = 1;

  if (!had_keys && !had_lock)
    return;

  fprintf(stderr,
          "Warning: contact '%s' has been used on this keychain before (%s). If the key files you "
          "are supplying now are the ORIGINAL copies from key generation, part of that key has "
          "already encrypted messages, and using it again breaks the one-time pad. Only supply key "
          "material that has never been used - either freshly generated keys, or the partially "
          "consumed files from %s%c itself.\n",
          name, had_keys ? "its key files are still present" : "a lock file from a previous contact remains",
          keychain_dir, PATH_SEPARATOR);
}

// Build path for contact's key file
static void build_key_path(const char *contact_name, const char *key_type,
                           char *path, size_t path_size)
{
  char dir[512];
  get_keychain_dir(dir, sizeof(dir));
  int written = snprintf(path, path_size, "%s" PATH_SEPARATOR_STR "%s_%s.key", dir, contact_name, key_type);
  // Ensure null termination if truncated
  if (written >= (int)path_size)
  {
    path[path_size - 1] = '\0';
  }
}

// A contact's name is not just a label: it is used verbatim to build the
// filenames of that contact's key files, its .meta file, its .lock file
// and its pending artifacts, all of which are meant to stay inside the
// keychain directory. Without validation, a name like "../../evil" would
// place those files anywhere the user can write, and a name containing a
// path separator could make two distinct contacts share one lock file -
// quietly defeating the mutual exclusion the lock exists to provide.
//
// Rejected: empty or over-long names, "." and "..", anything containing a
// path separator or a character that is illegal in a Windows filename,
// control characters, and '=' (which would corrupt the key=value .meta
// format the name is stored in). Everything else - spaces, dots,
// non-ASCII/UTF-8 names - is still allowed.
static int is_valid_contact_name(const char *name)
{
  if (!name || name[0] == '\0')
    return 0;
  if (strlen(name) >= MAX_NAME_LENGTH)
    return 0;
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
  {
    if (*p < 0x20 || *p == 0x7f)
      return 0;
    if (strchr("/\\:*?\"<>|=", (char)*p))
      return 0;
  }
  return 1;
}

static int reject_invalid_contact_name(const char *name)
{
  if (is_valid_contact_name(name))
    return 0;
  fprintf(stderr,
          "Error: Invalid contact name '%s' - names must be 1-%d characters and may not be "
          "\".\" or \"..\", contain a path separator (/ or \\), any of : * ? \" < > | = , "
          "or control characters\n",
          name ? name : "", MAX_NAME_LENGTH - 1);
  return -1;
}

// Initialize keychain
void init_keychain(void)
{
  memset(&g_keychain, 0, sizeof(Keychain));
  g_keychain.count = 0;
}

// Cleanup keychain memory
//
// Contacts own no heap allocations - key material lives in files and
// metadata is all fixed-size fields - so dropping the count is the whole
// job.
void cleanup_keychain(void)
{
  g_keychain.count = 0;
}

// Find a contact by name
Contact *find_contact(const char *name)
{
  for (int i = 0; i < g_keychain.count; i++)
  {
    if (strcmp(g_keychain.contacts[i].Name, name) == 0)
    {
      return &g_keychain.contacts[i];
    }
  }
  return NULL;
}

// Escape special characters for file storage
static void escape_string(const char *input, char *output, size_t max_output)
{
  size_t i, j;
  for (i = 0, j = 0; input[i] && j < max_output - 2; i++)
  {
    if (input[i] == '\\' || input[i] == '\n' || input[i] == '\r')
    {
      output[j++] = '\\';
      if (input[i] == '\n')
        output[j++] = 'n';
      else if (input[i] == '\r')
        output[j++] = 'r';
      else
        output[j++] = '\\';
    }
    else
    {
      output[j++] = input[i];
    }
  }
  output[j] = '\0';
}

static void unescape_string(const char *input, char *output, size_t max_output)
{
  size_t i, j;
  for (i = 0, j = 0; input[i] && j < max_output - 1; i++)
  {
    if (input[i] == '\\' && input[i + 1])
    {
      i++;
      if (input[i] == 'n')
        output[j++] = '\n';
      else if (input[i] == 'r')
        output[j++] = '\r';
      else
        output[j++] = input[i];
    }
    else
    {
      output[j++] = input[i];
    }
  }
  output[j] = '\0';
}

// Read the key=value fields of one contact's .meta file from an
// already-open stream, stopping at a blank line, a "[...]" section
// header, or EOF.
static void parse_contact_fields(FILE *f, Contact *c)
{
// Every field is bounded: the longest possible line is a key file path
// (512) or an escaped contact name (512), so a few KB is ample. Nothing
// stored here scales with message or key size.
#define FIELD_LINE_BUFFER_SIZE 8192
  char *line = malloc(FIELD_LINE_BUFFER_SIZE);
  char *value = malloc(FIELD_LINE_BUFFER_SIZE);
  if (!line || !value)
  {
    free(line);
    free(value);
    return;
  }

  while (fgets(line, FIELD_LINE_BUFFER_SIZE, f))
  {
    if (line[0] == '\n' || line[0] == '[')
      break;

    char key[256];
    // Split at the first '='; the value is copied manually so its length
    // is not capped by a sscanf field width (key file paths can be long)
    char *equals = strchr(line, '=');
    if (equals && sscanf(line, "%255[^=]", key) == 1)
    {
      // Copy everything after '=' to value
      strncpy(value, equals + 1, FIELD_LINE_BUFFER_SIZE - 1);
      value[FIELD_LINE_BUFFER_SIZE - 1] = '\0';
      // Remove trailing newline if present
      size_t len = strlen(value);
      if (len > 0 && value[len - 1] == '\n')
      {
        value[len - 1] = '\0';
      }
      if (strcmp(key, "Name") == 0)
      {
        unescape_string(value, c->Name, MAX_NAME_LENGTH);
      }
      else if (strcmp(key, "EncryptionKeyPath") == 0)
      {
        strncpy(c->EncryptionKeyPath, value, sizeof(c->EncryptionKeyPath) - 1);
      }
      else if (strcmp(key, "EncryptionKeySize") == 0)
      {
        c->EncryptionKeySize = (size_t)atoll(value);
      }
      else if (strcmp(key, "EncryptionKeyOffset") == 0)
      {
        c->EncryptionKeyOffset = (size_t)atoll(value);
      }
      else if (strcmp(key, "EncryptedSequence") == 0)
      {
        c->EncryptedSequence = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptionKeyPath") == 0)
      {
        strncpy(c->DecryptionKeyPath, value, sizeof(c->DecryptionKeyPath) - 1);
      }
      else if (strcmp(key, "DecryptionKeySize") == 0)
      {
        c->DecryptionKeySize = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptionKeyOffset") == 0)
      {
        c->DecryptionKeyOffset = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptedSequence") == 0)
      {
        c->DecryptedSequence = (size_t)atoll(value);
      }
      else if (strcmp(key, "RetryCount") == 0)
      {
        c->RetryCount = atoi(value);
        if (c->RetryCount < MIN_RETRY_COUNT)
          c->RetryCount = MIN_RETRY_COUNT;
        if (c->RetryCount > MAX_RETRY_COUNT)
          c->RetryCount = MAX_RETRY_COUNT;
      }
      else if (strcmp(key, "LastMessageSentAt") == 0)
      {
        c->LastMessageSentAt = (time_t)atoll(value);
      }
      else if (strcmp(key, "LastMessageReceivedAt") == 0)
      {
        c->LastMessageReceivedAt = (time_t)atoll(value);
      }
    }
  }

  free(line);
  free(value);
#undef FIELD_LINE_BUFFER_SIZE
}

// Small growable buffer used to build one contact's metadata content in
// memory before it is committed - this lets save_contact_meta hand the
// exact, complete, intended bytes to commit_write_verified() for a real
// read-back comparison, rather than trusting fprintf()'s return value.
typedef struct
{
  char *data;
  size_t len;
  size_t cap;
} GrowBuf;

static int gb_append(GrowBuf *g, const char *s, size_t n)
{
  if (g->len + n + 1 > g->cap)
  {
    size_t new_cap = g->cap ? g->cap * 2 : 4096;
    while (new_cap < g->len + n + 1)
      new_cap *= 2;
    char *nd = realloc(g->data, new_cap);
    if (!nd)
      return -1;
    g->data = nd;
    g->cap = new_cap;
  }
  memcpy(g->data + g->len, s, n);
  g->len += n;
  g->data[g->len] = '\0';
  return 0;
}

static int gb_printf(GrowBuf *g, const char *fmt, ...)
{
  char stackbuf[4096];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return -1;
  if ((size_t)n < sizeof(stackbuf))
    return gb_append(g, stackbuf, (size_t)n);

  char *big = malloc((size_t)n + 1);
  if (!big)
    return -1;
  va_start(ap, fmt);
  vsnprintf(big, (size_t)n + 1, fmt, ap);
  va_end(ap);
  int rc = gb_append(g, big, (size_t)n);
  free(big);
  return rc;
}

// Persist ONE contact to its own file, <keychain_dir>/<name>.meta -
// atomically and verified, via the same stage -> verify -> publish
// primitives used everywhere else in this module (commit_write_verified
// + commit_publish). Each contact's metadata lives in its own file, so
// concurrent operations on two different contacts write to two different
// files and cannot collide here at all - there is no shared mutable
// state between contacts for them to race on.
static int save_contact_meta(const char *keychain_dir, Contact *c)
{
  GrowBuf buf = {0};
  int build_failed = 0;

  char escaped_name[MAX_NAME_LENGTH * 2];
  escape_string(c->Name, escaped_name, sizeof(escaped_name));

  if (gb_printf(&buf, "[CONTACT]\n") != 0 ||
      gb_printf(&buf, "Name=%s\n", escaped_name) != 0 ||
      gb_printf(&buf, "EncryptionKeyPath=%s\n", c->EncryptionKeyPath) != 0 ||
      gb_printf(&buf, "EncryptionKeySize=%zu\n", c->EncryptionKeySize) != 0 ||
      gb_printf(&buf, "EncryptionKeyOffset=%zu\n", c->EncryptionKeyOffset) != 0 ||
      gb_printf(&buf, "EncryptedSequence=%zu\n", c->EncryptedSequence) != 0 ||
      gb_printf(&buf, "DecryptionKeyPath=%s\n", c->DecryptionKeyPath) != 0 ||
      gb_printf(&buf, "DecryptionKeySize=%zu\n", c->DecryptionKeySize) != 0 ||
      gb_printf(&buf, "DecryptionKeyOffset=%zu\n", c->DecryptionKeyOffset) != 0 ||
      gb_printf(&buf, "DecryptedSequence=%zu\n", c->DecryptedSequence) != 0)
  {
    build_failed = 1;
  }

  // Message content is deliberately never stored here - only fixed-size
  // bookkeeping. That keeps a .meta file the same handful of bytes no
  // matter how much traffic passes through the contact, and keeps this
  // function's write-fsync-read-back verification cheap enough to run on
  // every single operation.
  if (!build_failed &&
      (gb_printf(&buf, "RetryCount=%d\n", c->RetryCount) != 0 ||
       gb_printf(&buf, "LastMessageSentAt=%lld\n", (long long)c->LastMessageSentAt) != 0 ||
       gb_printf(&buf, "LastMessageReceivedAt=%lld\n", (long long)c->LastMessageReceivedAt) != 0))
  {
    build_failed = 1;
  }

  if (build_failed)
  {
    fprintf(stderr, "Error: Memory allocation failed while building metadata for '%s'\n", c->Name);
    free(buf.data);
    return -1;
  }

  char meta_path[600];
  snprintf(meta_path, sizeof(meta_path), "%s%c%s.meta", keychain_dir, PATH_SEPARATOR, c->Name);
  char tmp_path[620];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", meta_path);

  if (commit_write_verified(tmp_path, (const unsigned char *)buf.data, buf.len) != 0)
  {
    free(buf.data);
    return -1;
  }
  free(buf.data);

  commit_test_crash_point("after_meta_staged");

  return commit_publish(tmp_path, meta_path);
}

// Load a single contact from its own .meta file into g_keychain.
static void load_contact_meta_file(const char *path)
{
  if (g_keychain.count >= MAX_CONTACTS)
    return;

  FILE *f = fopen(path, "r");
  if (!f)
    return;

  char header[32];
  if (!fgets(header, sizeof(header), f))
  {
    fclose(f);
    return;
  }
  // First line is the "[CONTACT]" marker written by save_contact_meta();
  // remaining lines are key=value fields.

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  parse_contact_fields(f, c);
  fclose(f);

  // Validate here too, not only on add: this is the single choke point
  // every contact passes through before anything builds a file path from
  // its name, so a hand-edited or hand-planted .meta file can't smuggle
  // one past the checks in add_contact/add_contact_with_keys.
  if (!is_valid_contact_name(c->Name))
  {
    if (c->Name[0] != '\0')
      fprintf(stderr, "Warning: ignoring '%s' - it declares an invalid contact name\n", path);
    memset(c, 0, sizeof(Contact));
    return;
  }

  g_keychain.count++;
}

// Load keychain: reads every contact from its own .meta file under the
// keychain directory.
//
// This is a pure reader - it writes nothing, and must stay that way.
// It runs both before any lock is held (process startup) and again after
// a contact's lock is acquired; if it wrote, two processes starting at
// once could each persist their own stale view of a contact, one
// overwriting offsets the other had already committed. Reading only
// makes that impossible by construction.
//
// A contact exists if and only if it has a <name>.meta file in the
// keychain directory; nothing else in the directory is consulted.
int load_keychain(void)
{
  cleanup_keychain();
  init_keychain();

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Every contact lives in its own <name>.meta file inside the keychain
  // directory - load each one. opendir/readdir/closedir come from
  // platform.h, which is a real dirent-backed implementation on POSIX
  // and a FindFirstFile/FindNextFile-backed shim on Windows, so this
  // loop is identical on both platforms.
  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; // brand new keychain - nothing to load yet

  struct dirent *entry;
  while ((entry = readdir(d)) != NULL)
  {
    size_t name_len = strlen(entry->d_name);
    if (name_len <= 5 || strcmp(entry->d_name + name_len - 5, ".meta") != 0)
      continue;

    char full_path[600];
    int written = snprintf(full_path, sizeof(full_path), "%s%c%s",
                           keychain_dir, PATH_SEPARATOR, entry->d_name);
    if (written < 0 || (size_t)written >= sizeof(full_path))
    {
      fprintf(stderr, "Warning: skipping '%s' - its full path is too long\n", entry->d_name);
      continue;
    }
    load_contact_meta_file(full_path);
  }
  closedir(d);

  return 0;
}


// Add a contact. Runs with this contact's lock already held and the
// keychain freshly reloaded under it - see add_contact().
static int add_contact_locked(const char *name, const char *keychain_dir)
{
  if (g_keychain.count >= MAX_CONTACTS)
  {
    fprintf(stderr, "Error: Maximum contacts reached\n");
    return -1;
  }

  if (find_contact(name))
  {
    fprintf(stderr, "Error: Contact '%s' already exists\n", name);
    return -1;
  }

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  strncpy(c->Name, name, MAX_NAME_LENGTH - 1);
  c->RetryCount = 0;

  g_keychain.count++;

  return save_contact_meta(keychain_dir, c);
}

int add_contact(const char *name)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Hold this contact's lock across the existence check and the write -
  // the same per-contact lock encrypt/decrypt/remove take. Without it two
  // concurrent adds of one name both see "does not exist" and the slower
  // writer is silently lost, and an add can race a remove of the same
  // name. The lock name is built from the contact name, so validation
  // above must have passed first.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
    return -1;

  // Re-read the on-disk state now that the lock is held: another process
  // may have added or removed this contact while we waited for the lock,
  // so the snapshot loaded at process start (without the lock) can be stale.
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }

  int result = add_contact_locked(name, keychain_dir);
  contact_lock_release(&lock);
  return result;
}

// Add a contact with key files. Runs with this contact's lock already
// held and the keychain freshly reloaded under it - see
// add_contact_with_keys(). Holding the lock is what makes the
// cross-contact overlap scan below read a stable set of other contacts:
// without it, a concurrent add of the same name could also pass its own
// existence check and both would write, and the reloaded view could go
// stale mid-scan.
static int add_contact_with_keys_locked(const char *name, const char *encryption_key_file,
                                        const char *decryption_key_file, const char *keychain_dir)
{
  if (g_keychain.count >= MAX_CONTACTS)
  {
    fprintf(stderr, "Error: Maximum contacts reached\n");
    return -1;
  }

  if (find_contact(name))
  {
    fprintf(stderr, "Error: Contact '%s' already exists\n", name);
    return -1;
  }

  // Get key file sizes (without loading into memory). otp_file_size()
  // rather than stat(): the Windows CRT's struct stat carries a 32-bit
  // st_size, which would silently truncate the size of any key over 2GB.
  unsigned long long enc_size_64, dec_size_64;
  if (otp_file_size(encryption_key_file, &enc_size_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat encryption key file '%s': %s\n",
            encryption_key_file, strerror(errno));
    return -1;
  }
  if (otp_file_size(decryption_key_file, &dec_size_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat decryption key file '%s': %s\n",
            decryption_key_file, strerror(errno));
    return -1;
  }

  // Validate on the 64-bit sizes BEFORE narrowing to size_t: on a 32-bit
  // platform the cast itself truncates, so checking afterwards would let
  // an oversized key wrap around and slip past with a bogus small size.
  // On such platforms size_t's own range is the effective ceiling.
  unsigned long long max_key = MAX_KEY_SIZE;
  if ((unsigned long long)SIZE_MAX < max_key)
    max_key = (unsigned long long)SIZE_MAX;

  if (enc_size_64 > max_key)
  {
    fprintf(stderr, "Error: Encryption key file too large (max %llu bytes)\n",
            max_key);
    return -1;
  }
  if (dec_size_64 > max_key)
  {
    fprintf(stderr, "Error: Decryption key file too large (max %llu bytes)\n",
            max_key);
    return -1;
  }

  size_t enc_size = (size_t)enc_size_64;
  size_t dec_size = (size_t)dec_size_64;
  if (enc_size == 0 || dec_size == 0)
  {
    fprintf(stderr, "Error: Key files cannot be empty\n");
    return -1;
  }

  KeyOverlap overlap = key_files_overlap(encryption_key_file, decryption_key_file,
                                         enc_size, dec_size);
  if (overlap == KEY_OVERLAP_UNKNOWN)
  {
    // Fail closed: accepting an identical pair here would silently break
    // the pad forever, while refusing costs only a retry. This is the one
    // moment the mistake is detectable - once copied into the keychain the
    // two files are indistinguishable from a legitimately distinct pair.
    fprintf(stderr,
            "Error: Could not compare '%s' and '%s' to verify they hold different key "
            "material (a file could not be read, or memory for the comparison could not "
            "be allocated). Refusing to add the contact rather than risk installing one "
            "pad for both directions - resolve the failure and retry.\n",
            encryption_key_file, decryption_key_file);
    return -1;
  }
  if (overlap != KEY_OVERLAP_NONE)
  {
    fprintf(stderr,
            "Error: '%s' and '%s' contain the same key material%s. A contact needs two DIFFERENT "
            "one-time pads - one for sending, one for receiving. Using one pad for both means the "
            "bytes that encrypt an outgoing message also decrypt an incoming one, so the same key "
            "range covers two messages and the pad is broken. Generate a pair with "
            "--new-key-pair, which produces the two distinct keys this expects.\n",
            encryption_key_file, decryption_key_file,
            overlap == KEY_OVERLAP_IDENTICAL
                ? ""
                : (overlap == KEY_OVERLAP_PREFIX
                       ? " - the smaller file is the beginning of the larger one, so the whole of it "
                         "is key that the larger file also covers"
                       : (overlap == KEY_OVERLAP_SUFFIX
                              ? " - the smaller file is the tail of the larger one, which is what a partially "
                                "consumed key looks like; every byte it holds is still "
                                "present in the larger file"
                              : " - a stretch of one appears inside the other at an interior offset, which "
                                "is what a pad trimmed at both ends (or two windows cut from one pad) "
                                "looks like; every shared byte is one pad serving two roles")));
    return -1;
  }

  // The pair check above only rules out overlap between the two candidate
  // files themselves. The same pad must also not already be installed for
  // any OTHER contact: two contacts each consume their copy from its own
  // start, so shared material means two different messages encrypted or
  // decrypted with the same bytes. One shape is treated differently - the
  // mirrored pair (candidate enc = an existing dec, candidate dec = an
  // existing enc), which is how a single machine legitimately operates
  // both endpoints of its own pads (e.g. loopback testing in one
  // directory). That is allowed with a warning; same-direction overlap is
  // refused outright.
  struct
  {
    const char *path;
    size_t size;
    const char *word;
  } cands[2] = {
      {encryption_key_file, enc_size, "encryption"},
      {decryption_key_file, dec_size, "decryption"}};

  for (int i = 0; i < g_keychain.count; i++)
  {
    Contact *other = &g_keychain.contacts[i];
    struct
    {
      const char *path;
      const char *word;
    } theirs[2] = {
        {other->EncryptionKeyPath, "encryption"},
        {other->DecryptionKeyPath, "decryption"}};

    for (int t = 0; t < 2; t++)
    {
      if (theirs[t].path[0] == '\0')
        continue;
      unsigned long long their_size;
      if (otp_file_size(theirs[t].path, &their_size) != 0)
      {
        fprintf(stderr,
                "Error: Could not read contact '%s's %s key to rule out shared key material "
                "with the new contact. Refusing to add rather than risk installing an "
                "already-installed pad - resolve the failure and retry.\n",
                other->Name, theirs[t].word);
        return -1;
      }
      if (their_size == 0)
        continue; // fully consumed - nothing left to overlap with

      // A key too large for this build's size_t (possible when a keychain
      // written by a 64-bit build is opened by a 32-bit one) cannot be
      // compared without truncating it, which could hide an overlap - so
      // refuse to add, same as any other unverifiable-overlap failure.
      size_t their_size_sz;
      if (otp_size_to_size_t(their_size, &their_size_sz) != 0)
      {
        fprintf(stderr,
                "Error: contact '%s's %s key is too large for this build to rule out shared "
                "key material with the new contact. Refusing to add rather than risk "
                "installing an already-installed pad.\n",
                other->Name, theirs[t].word);
        return -1;
      }

      for (int cnd = 0; cnd < 2; cnd++)
      {
        KeyOverlap cross = key_files_overlap(cands[cnd].path, theirs[t].path,
                                             cands[cnd].size, their_size_sz);
        if (cross == KEY_OVERLAP_UNKNOWN)
        {
          fprintf(stderr,
                  "Error: Could not compare '%s' against contact '%s's %s key to rule out "
                  "shared key material. Refusing to add the contact rather than risk "
                  "installing one pad twice - resolve the failure and retry.\n",
                  cands[cnd].path, other->Name, theirs[t].word);
          return -1;
        }
        if (cross == KEY_OVERLAP_NONE)
          continue;
        if (cnd == t)
        {
          fprintf(stderr,
                  "Error: '%s' holds the same key material as contact '%s's %s key. One pad "
                  "installed under two contacts is consumed twice from its own start, so two "
                  "different messages would share key bytes - a broken one-time pad. Every "
                  "contact needs key material no other contact holds.\n",
                  cands[cnd].path, other->Name, theirs[t].word);
          return -1;
        }
        fprintf(stderr,
                "Warning: '%s' matches contact '%s's %s key - this pair looks like the "
                "other endpoint of that contact's pads. That is only safe when this "
                "keychain deliberately operates both correspondents (for example loopback "
                "testing in one directory); between two real contacts a shared pad breaks.\n",
                cands[cnd].path, other->Name, theirs[t].word);
      }
    }
  }

  // Keys of *removed* contacts no longer exist to be compared against;
  // the spent-heads registry is what remains of them. A candidate that
  // contains a recorded spent head is (a copy of) an original whose
  // opening bytes already encrypted or decrypted messages here.
  SpentHead *spent = NULL;
  size_t spent_count = 0;
  if (spent_heads_load(keychain_dir, &spent, &spent_count) != 0)
  {
    fprintf(stderr,
            "Error: Could not read the spent-key registry (%s%cspent_heads) to check the "
            "supplied keys against previously consumed material. Refusing to add the "
            "contact rather than risk re-installing a spent pad - resolve the failure "
            "and retry.\n",
            keychain_dir, PATH_SEPARATOR);
    return -1;
  }
  for (int cnd = 0; cnd < 2 && spent_count > 0; cnd++)
  {
    size_t m = 0;
    int hit = spent_heads_scan_file(cands[cnd].path, spent, spent_count, &m);
    if (hit < 0)
    {
      fprintf(stderr,
              "Error: Could not scan '%s' against the spent-key registry. Refusing to add "
              "the contact rather than risk re-installing a spent pad - resolve the "
              "failure and retry.\n",
              cands[cnd].path);
      free(spent);
      return -1;
    }
    if (hit == 1)
    {
      int cand_is_enc = (cnd == 0);
      int spent_as_enc = (strcmp(spent[m].direction, "enc") == 0);
      if (!cand_is_enc && spent_as_enc)
      {
        // The mirrored-endpoint case again, this time against history: a
        // decryption key holding an enc-spent head will decrypt exactly
        // the messages those bytes already encrypted - no new exposure.
        fprintf(stderr,
                "Warning: '%s' contains the head of key material this keychain already "
                "spent for encryption. As a decryption key it will decrypt exactly those "
                "already-sent messages - sensible only when this keychain deliberately "
                "acts as the other endpoint of its own pads.\n",
                cands[cnd].path);
      }
      else
      {
        fprintf(stderr,
                "Error: '%s' contains key material that was already spent on this keychain: "
                "its bytes include the head of a %s key consumed by a previous message "
                "(possibly under a contact that has since been removed). Using them again "
                "would cover two messages with one pad. Supply only never-used key "
                "material, or the partially consumed remainder file if you kept it.\n",
                cands[cnd].path, spent_as_enc ? "encryption" : "decryption");
        free(spent);
        return -1;
      }
    }
  }
  free(spent);

  // Build destination paths
  char enc_dest[512], dec_dest[512];
  build_key_path(name, "enc", enc_dest, sizeof(enc_dest));
  build_key_path(name, "dec", dec_dest, sizeof(dec_dest));

  // Copy both key files into the keychain, 0600 and fsynced
  if (copy_key_file(encryption_key_file, enc_dest) != 0)
    return -1;

  if (copy_key_file(decryption_key_file, dec_dest) != 0)
  {
    unlink(enc_dest);
    return -1;
  }

  // Create contact with paths to key files
  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));

  snprintf(c->Name, MAX_NAME_LENGTH, "%s", name);
  snprintf(c->EncryptionKeyPath, sizeof(c->EncryptionKeyPath), "%s", enc_dest);
  c->EncryptionKeySize = enc_size;
  c->EncryptionKeyOffset = 0;
  snprintf(c->DecryptionKeyPath, sizeof(c->DecryptionKeyPath), "%s", dec_dest);
  c->DecryptionKeySize = dec_size;
  c->DecryptionKeyOffset = 0;
  c->EncryptedSequence = 0;
  c->DecryptedSequence = 0;
  c->RetryCount = 0;
  c->LastMessageSentAt = 0;
  c->LastMessageReceivedAt = 0;

  g_keychain.count++;

  int result = save_contact_meta(keychain_dir, c);
  if (result == 0)
  {
    printf("Contact '%s' added with keys:\n", name);
    printf("  Encryption key: %zu bytes from %s\n", enc_size, encryption_key_file);
    printf("  Decryption key: %zu bytes from %s\n", dec_size, decryption_key_file);
  }

  return result;
}

int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Sample the "name used before" signal *before* acquiring this contact's
  // lock: acquiring it creates <name>.lock, which is one of the very
  // signals this warning keys on, so reading it afterwards would make the
  // warning fire on every add. It only reads files and needs no locking.
  warn_if_name_previously_used(keychain_dir, name);

  // Same per-contact lock discipline as encrypt/decrypt/remove - see
  // add_contact() for why an add must hold it too.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
    return -1;

  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }

  int result = add_contact_with_keys_locked(name, encryption_key_file,
                                            decryption_key_file, keychain_dir);
  contact_lock_release(&lock);
  return result;
}

// Remove a contact
// Defined with the other last-payload-copy helpers further down; needed
// here because remove_contact must delete a contact's kept copies too.
static void last_copy_path(const char *keychain_dir, const char *contact_name,
                           int is_encrypt, char *path, size_t path_size);

int remove_contact(const char *name)
{
  int index = -1;
  for (int i = 0; i < g_keychain.count; i++)
  {
    if (strcmp(g_keychain.contacts[i].Name, name) == 0)
    {
      index = i;
      break;
    }
  }

  if (index == -1)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", name);
    return -1;
  }

  // Hold the same per-contact lock encrypt/decrypt use, so a removal
  // can't race with an in-flight operation that's mid-way through
  // reading or truncating this contact's key files.
  char keychain_dir[512];
  int have_dir = (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) == 0);

  ContactLock lock;
  int locked = 0;
  if (have_dir)
  {
    if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
      return -1;
    locked = 1;

    // Reload from disk now that we hold the lock, and re-find the
    // contact by name (not by the index computed before the wait) in
    // case concurrent activity changed its position or removed it.
    //
    // A failed reload has to abort: load_keychain() empties the in-memory
    // keychain before it can fail, so carrying on with the pre-reload
    // `index` would read a zeroed contact and then decrement a count that
    // is already 0 down to -1.
    if (load_keychain() != 0)
    {
      fprintf(stderr, "Error: Failed to reload keychain\n");
      contact_lock_release(&lock);
      return -1;
    }

    index = -1;
    for (int i = 0; i < g_keychain.count; i++)
    {
      if (strcmp(g_keychain.contacts[i].Name, name) == 0)
      {
        index = i;
        break;
      }
    }
    if (index == -1)
    {
      fprintf(stderr, "Error: Contact '%s' not found\n", name);
      contact_lock_release(&lock);
      return -1;
    }
  }

  // Delete key files, and any staging sibling a crash mid-truncation may
  // have left next to them - that file holds this contact's key material,
  // so removing the key file without it would leave the secret behind.
  char sibling[600];
  if (g_keychain.contacts[index].EncryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].EncryptionKeyPath);
    snprintf(sibling, sizeof(sibling), "%s.tmp", g_keychain.contacts[index].EncryptionKeyPath);
    unlink(sibling);
  }
  if (g_keychain.contacts[index].DecryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].DecryptionKeyPath);
    snprintf(sibling, sizeof(sibling), "%s.tmp", g_keychain.contacts[index].DecryptionKeyPath);
    unlink(sibling);
  }

  // Clean up any leftover staged pending artifacts for this contact so
  // they don't linger in .keychain/ forever, and the kept last-payload
  // copies: removing a contact must take every trace of message content
  // with it (the empty .lock file below is the one deliberate exception).
  if (have_dir)
  {
    commit_discard_all_pending(keychain_dir, name);
    char last[600];
    last_copy_path(keychain_dir, name, 1, last, sizeof(last));
    unlink(last);
    last_copy_path(keychain_dir, name, 0, last, sizeof(last));
    unlink(last);
  }

  // Shift remaining contacts (in-memory bookkeeping only)
  for (int i = index; i < g_keychain.count - 1; i++)
  {
    g_keychain.contacts[i] = g_keychain.contacts[i + 1];
  }

  g_keychain.count--;

  // Each contact owns its own metadata file, so removing one is just
  // deleting that file - no other contact's file is ever touched.
  int result = 0;
  if (have_dir)
  {
    char meta_path[600];
    snprintf(meta_path, sizeof(meta_path), "%s%c%s.meta", keychain_dir, PATH_SEPARATOR, name);
    if (unlink(meta_path) != 0 && errno != ENOENT)
    {
      fprintf(stderr, "Error: Failed to remove metadata file %s: %s\n", meta_path, strerror(errno));
      result = -1;
    }

    char meta_tmp[620];
    snprintf(meta_tmp, sizeof(meta_tmp), "%s.tmp", meta_path);
    unlink(meta_tmp);
  }

  if (locked)
  {
    // The empty .lock file is deliberately left in place. Unlinking it
    // would break mutual exclusion for anyone already blocked on it:
    // flock() locks an *inode*, so a waiter holding the old, now-unlinked
    // inode and a newcomer that creates a fresh file at the same path
    // would each hold "the" lock simultaneously. That matters as soon as
    // a contact is re-added under the same name. A zero-byte file is a
    // very cheap price for not having to reason about that.
    contact_lock_release(&lock);
  }

  return result;
}

// Check if contact exists
int has_contact(const char *name)
{
  return find_contact(name) != NULL;
}

// List all contacts
void list_contacts(void)
{
  if (g_keychain.count == 0)
  {
    printf("No contacts in keychain\n");
    return;
  }

  printf("Contacts (%d):\n", g_keychain.count);
  for (int i = 0; i < g_keychain.count; i++)
  {
    printf("  - %s\n", g_keychain.contacts[i].Name);
  }
}

// Show contact details
void show_contact(const char *name)
{
  Contact *c = find_contact(name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", name);
    return;
  }

  printf("\nContact: %s\n", c->Name);
  printf("  EncryptionKey: ******* (%zu bytes)\n", c->EncryptionKeySize);
  printf("  EncryptionKeyOffset: %zu\n", c->EncryptionKeyOffset);
  printf("  EncryptedSequence: %zu\n", c->EncryptedSequence);
  printf("  DecryptionKey: ******* (%zu bytes)\n", c->DecryptionKeySize);
  printf("  DecryptionKeyOffset: %zu\n", c->DecryptionKeyOffset);
  printf("  DecryptedSequence: %zu\n", c->DecryptedSequence);

  printf("  RetryCount: %d\n", c->RetryCount);

  if (c->LastMessageSentAt > 0)
  {
    printf("  LastMessageSentAt: %s", ctime(&c->LastMessageSentAt));
  }
  else
  {
    printf("  LastMessageSentAt: never\n");
  }

  if (c->LastMessageReceivedAt > 0)
  {
    printf("  LastMessageReceivedAt: %s", ctime(&c->LastMessageReceivedAt));
  }
  else
  {
    printf("  LastMessageReceivedAt: never\n");
  }
  printf("\n");
}

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
static int truncate_key_file(const char *direction, const char *key_path,
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
