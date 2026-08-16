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
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#define getpid _getpid
#define fsync _commit
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

  if (read_failed || fflush(dst) != 0 || fsync(fileno(dst)) != 0)
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
// truncated, so the natural leftovers of this tool - a ".next" file from
// the direct key-file mode, a partially consumed key from .keychain/ -
// are *suffixes* of the pad they came from. Handing over a pad and its
// own leftover is overlap just as total as handing over the same file
// twice, and the sizes differ precisely because some of it was already
// spent. A truncated head of a pad is the mirror image of that case.
//
// Both alignments are therefore compared over the whole of the shorter
// file: the two fronts against each other (prefix), and the two tails
// against each other (suffix). Comparison stops at the first differing
// byte, so two genuinely independent pads cost about one chunk of I/O no
// matter how large they are - it is only actually-overlapping files that
// are read to the end.
#define KEY_COMPARE_CHUNK (1024 * 1024)

typedef enum
{
  KEY_OVERLAP_NONE = 0,
  KEY_OVERLAP_IDENTICAL, // same size, same bytes
  KEY_OVERLAP_PREFIX,    // the shorter file is the head of the longer
  KEY_OVERLAP_SUFFIX,    // the shorter file is the tail of the longer
  KEY_OVERLAP_UNKNOWN    // comparison could not be carried out at all
} KeyOverlap;

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

  // Fronts aligned. With equal sizes this is a whole-file comparison and
  // settles the identical case outright.
  int front = file_ranges_equal(path_a, 0, path_b, 0, shorter);
  if (front < 0)
    return KEY_OVERLAP_UNKNOWN;
  if (front)
    return (size_a == size_b) ? KEY_OVERLAP_IDENTICAL : KEY_OVERLAP_PREFIX;

  if (size_a == size_b)
    return KEY_OVERLAP_NONE;

  // Tails aligned: the shorter file against the last `shorter` bytes of
  // the longer one. This is the ".next"/partially-consumed-key case.
  int tail = file_ranges_equal(path_a, size_a - shorter, path_b, size_b - shorter, shorter);
  if (tail < 0)
    return KEY_OVERLAP_UNKNOWN;
  if (tail)
    return KEY_OVERLAP_SUFFIX;

  return KEY_OVERLAP_NONE;
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


// Add a contact
int add_contact(const char *name)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

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

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  strncpy(c->Name, name, MAX_NAME_LENGTH - 1);
  c->RetryCount = 0;

  g_keychain.count++;

  return save_contact_meta(keychain_dir, c);
}

// Add a contact with key files
int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

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

  size_t enc_size = (size_t)enc_size_64;
  size_t dec_size = (size_t)dec_size_64;

  if (enc_size > MAX_KEY_SIZE)
  {
    fprintf(stderr, "Error: Encryption key file too large (max %llu bytes)\n",
            (unsigned long long)MAX_KEY_SIZE);
    return -1;
  }
  if (dec_size > MAX_KEY_SIZE)
  {
    fprintf(stderr, "Error: Decryption key file too large (max %llu bytes)\n",
            (unsigned long long)MAX_KEY_SIZE);
    return -1;
  }
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
                       : " - the smaller file is the tail of the larger one, which is what a partially "
                         "consumed key or a \".next\" file looks like; every byte it holds is still "
                         "present in the larger file"));
    return -1;
  }

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  warn_if_name_previously_used(keychain_dir, name);

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

// Remove a contact
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
  // they don't linger in .keychain/ forever.
  if (have_dir)
  {
    commit_discard_all_pending(keychain_dir, name);
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
  size_t actual = (size_t)actual_64;

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
    commit_discard_path(rec.pending_path);
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
  commit_discard_path(pending_final_path);

  // Print info to stderr
  fprintf(stderr, "Used %zu bytes from encryption key for contact '%s'\n", total_bytes, contact_name);
  fprintf(stderr, "Remaining encryption key: %zu bytes\n", c->EncryptionKeySize);

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
    commit_discard_path(rec.pending_path);
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
  commit_discard_path(pending_final_path);

  // Print info to stderr
  fprintf(stderr, "Used %zu bytes from decryption key for contact '%s'\n", total_bytes, contact_name);
  fprintf(stderr, "Remaining decryption key: %zu bytes\n", c->DecryptionKeySize);

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
