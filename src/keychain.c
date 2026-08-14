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
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

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
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#endif

// Global keychain instance
Keychain g_keychain = {0};

// Get keychain directory path (creates if doesn't exist)
static int get_keychain_dir(const char *keychain_file, char *dir_path, size_t dir_path_size)
{
  // Extract directory from keychain file path
  const char *last_slash = strrchr(keychain_file, PATH_SEPARATOR);
  if (last_slash)
  {
    size_t dir_len = last_slash - keychain_file;
    if (dir_len + 12 >= dir_path_size)
      return -1; // +12 for separator + ".keychain\0"
    memcpy(dir_path, keychain_file, dir_len);
    dir_path[dir_len] = '\0';
    strcat(dir_path, PATH_SEPARATOR_STR ".keychain");
  }
  else
  {
    // keychain.txt is in current directory
    strncpy(dir_path, ".keychain", dir_path_size);
  }

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

// Build path for contact's key file
static void build_key_path(const char *keychain_file, const char *contact_name,
                           const char *key_type, char *path, size_t path_size)
{
  char dir[512];
  get_keychain_dir(keychain_file, dir, sizeof(dir));
  int written = snprintf(path, path_size, "%s" PATH_SEPARATOR_STR "%s_%s.key", dir, contact_name, key_type);
  // Ensure null termination if truncated
  if (written >= (int)path_size)
  {
    path[path_size - 1] = '\0';
  }
}

// Initialize keychain
void init_keychain(void)
{
  memset(&g_keychain, 0, sizeof(Keychain));
  g_keychain.count = 0;
}

// Cleanup keychain memory
void cleanup_keychain(void)
{
  for (int i = 0; i < g_keychain.count; i++)
  {
    // Only need to free LastMessageSent now (keys are in files)
    if (g_keychain.contacts[i].LastMessageSent)
    {
      free(g_keychain.contacts[i].LastMessageSent);
      g_keychain.contacts[i].LastMessageSent = NULL;
    }
  }
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

// Base64 encoding helper for binary data storage
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *data, size_t input_length, char *output)
{
  size_t i, j;
  for (i = 0, j = 0; i < input_length;)
  {
    uint32_t octet_a = i < input_length ? data[i++] : 0;
    uint32_t octet_b = i < input_length ? data[i++] : 0;
    uint32_t octet_c = i < input_length ? data[i++] : 0;
    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

    output[j++] = base64_table[(triple >> 18) & 0x3F];
    output[j++] = base64_table[(triple >> 12) & 0x3F];
    output[j++] = base64_table[(triple >> 6) & 0x3F];
    output[j++] = base64_table[triple & 0x3F];
  }

  size_t mod = input_length % 3;
  if (mod == 1)
  {
    output[j - 2] = '=';
    output[j - 1] = '=';
  }
  else if (mod == 2)
  {
    output[j - 1] = '=';
  }
  output[j] = '\0';
}

static int base64_decode_value(char c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  if (c == '=')
    return -1;
  return -2;
}

static size_t base64_decode(const char *input, unsigned char *output, size_t max_output)
{
  size_t i, j;
  size_t len = strlen(input);

  for (i = 0, j = 0; i < len && j < max_output;)
  {
    int a = base64_decode_value(input[i++]);
    int b = (i < len) ? base64_decode_value(input[i++]) : -1;
    int c = (i < len) ? base64_decode_value(input[i++]) : -1;
    int d = (i < len) ? base64_decode_value(input[i++]) : -1;

    if (a < 0 || b < 0)
      break;

    output[j++] = (a << 2) | (b >> 4);
    if (c >= 0 && j < max_output)
    {
      output[j++] = (b << 4) | (c >> 2);
    }
    if (d >= 0 && j < max_output)
    {
      output[j++] = (c << 6) | d;
    }
  }

  return j;
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

// Read key=value fields for one contact record from an already-open
// stream, until a blank line, a new "[...]" section, or EOF. Used both
// for a single contact's own .meta file and, during the one-time legacy
// migration below, for each block of an old combined keychain.txt.
static void parse_contact_fields(FILE *f, Contact *c)
{
// Use a reasonable line buffer size for parsing (keys are base64 encoded, ~1.33x original)
// 16MB buffer allows for ~12MB binary keys per line
#define FIELD_LINE_BUFFER_SIZE (16 * 1024 * 1024)
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
    {
      fseek(f, -(long)strlen(line), SEEK_CUR);
      break;
    }

    char key[256];
    // Parse key=value manually to avoid sscanf width limitations
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
      else if (strcmp(key, "Sequence") == 0)
      {
        // Legacy field - map to EncryptedSequence for backwards compatibility
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
      else if (strcmp(key, "LastMessageSent") == 0)
      {
        // Decode base64 LastMessageSent
        size_t value_len = strlen(value);
        if (value_len > 0)
        {
          c->LastMessageSent = malloc(value_len); // Decoded will be smaller
          if (c->LastMessageSent)
          {
            c->LastMessageSentSize = base64_decode(value, c->LastMessageSent, value_len);
          }
        }
      }
      else if (strcmp(key, "LastMessageSentSize") == 0)
      {
        c->LastMessageSentSize = (size_t)atoll(value);
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
// + commit_publish). Because every contact's metadata now lives in its
// own file instead of one shared keychain.txt, two different contacts
// can never collide here - this is what actually eliminates the
// cross-contact metadata race between concurrent operations on different
// contacts, rather than merely serializing around it.
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

  if (!build_failed)
  {
    if (c->LastMessageSent && c->LastMessageSentSize > 0)
    {
      char *msg_b64 = malloc(c->LastMessageSentSize * 4 / 3 + 4);
      if (!msg_b64)
      {
        build_failed = 1;
      }
      else
      {
        base64_encode(c->LastMessageSent, c->LastMessageSentSize, msg_b64);
        int rc = gb_printf(&buf, "LastMessageSent=%s\n", msg_b64);
        free(msg_b64);
        if (rc != 0)
          build_failed = 1;
      }
    }
    else if (gb_printf(&buf, "LastMessageSent=\n") != 0)
    {
      build_failed = 1;
    }
  }

  if (!build_failed &&
      (gb_printf(&buf, "LastMessageSentSize=%zu\n", c->LastMessageSentSize) != 0 ||
       gb_printf(&buf, "RetryCount=%d\n", c->RetryCount) != 0 ||
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

  if (c->Name[0] != '\0')
    g_keychain.count++;
}

// One-time, self-healing migration from the legacy combined keychain.txt
// (older installs) to one .meta file per contact. Idempotent and
// crash-safe: re-running it is harmless, since each contact is rewritten
// through the same verified-write-then-publish path as any other save,
// and the legacy file is only renamed out of the way as the LAST step,
// once every contact from it has been written out successfully - so an
// interrupted migration just re-runs in full on the next load rather
// than silently losing whatever hadn't been converted yet.
static void migrate_legacy_keychain_if_needed(const char *legacy_path, const char *keychain_dir)
{
  FILE *legacy = fopen(legacy_path, "r");
  if (!legacy)
    return; // nothing to migrate

#define LEGACY_LINE_BUFFER_SIZE (16 * 1024 * 1024)
  char *line = malloc(LEGACY_LINE_BUFFER_SIZE);
  if (!line)
  {
    fclose(legacy);
    return;
  }

  int migrated = 0;
  while (fgets(line, LEGACY_LINE_BUFFER_SIZE, legacy))
  {
    if (line[0] == '#' || line[0] == '\n')
      continue;
    if (strncmp(line, "[CONTACT]", 9) != 0)
      continue;

    Contact c;
    memset(&c, 0, sizeof(c));
    parse_contact_fields(legacy, &c);
    if (c.Name[0] != '\0')
    {
      save_contact_meta(keychain_dir, &c);
      migrated++;
    }
    if (c.LastMessageSent)
      free(c.LastMessageSent);
  }

  free(line);
  fclose(legacy);
#undef LEGACY_LINE_BUFFER_SIZE

  char backup_path[600];
  snprintf(backup_path, sizeof(backup_path), "%s.migrated", legacy_path);
  if (rename(legacy_path, backup_path) == 0)
  {
    fprintf(stderr,
            "Note: migrated %d contact(s) from legacy '%s' to per-contact files in '%s%c' "
            "(original preserved as '%s')\n",
            migrated, legacy_path, keychain_dir, PATH_SEPARATOR, backup_path);
  }
}

// Load keychain: migrates a legacy combined keychain.txt if one is found,
// then loads every contact from its own .meta file under the keychain
// directory.
int load_keychain(const char *file_path)
{
  // file_path may alias g_keychain.filepath itself (callers reloading
  // after acquiring a per-contact lock do exactly this). init_keychain()
  // below memsets the whole g_keychain struct, including filepath, which
  // would invalidate file_path out from under us if it pointed there -
  // so take our own copy up front, before touching anything.
  char file_path_copy[sizeof(g_keychain.filepath)];
  snprintf(file_path_copy, sizeof(file_path_copy), "%s", file_path);
  file_path = file_path_copy;

  cleanup_keychain();
  init_keychain();
  snprintf(g_keychain.filepath, sizeof(g_keychain.filepath), "%s", file_path);

  char keychain_dir[512];
  if (get_keychain_dir(file_path, keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  migrate_legacy_keychain_if_needed(file_path, keychain_dir);

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
    snprintf(full_path, sizeof(full_path), "%s%c%s", keychain_dir, PATH_SEPARATOR, entry->d_name);
    load_contact_meta_file(full_path);
  }
  closedir(d);

  return 0;
}


// Add a contact
int add_contact(const char *name)
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

  char keychain_dir[512];
  if (get_keychain_dir(g_keychain.filepath, keychain_dir, sizeof(keychain_dir)) != 0)
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

  // Get key file sizes (without loading into memory)
  struct stat enc_st, dec_st;
  if (stat(encryption_key_file, &enc_st) != 0)
  {
    fprintf(stderr, "Error: Cannot stat encryption key file '%s': %s\n",
            encryption_key_file, strerror(errno));
    return -1;
  }
  if (stat(decryption_key_file, &dec_st) != 0)
  {
    fprintf(stderr, "Error: Cannot stat decryption key file '%s': %s\n",
            decryption_key_file, strerror(errno));
    return -1;
  }

  size_t enc_size = enc_st.st_size;
  size_t dec_size = dec_st.st_size;

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

  char keychain_dir[512];
  if (get_keychain_dir(g_keychain.filepath, keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Build destination paths
  char enc_dest[512], dec_dest[512];
  build_key_path(g_keychain.filepath, name, "enc", enc_dest, sizeof(enc_dest));
  build_key_path(g_keychain.filepath, name, "dec", dec_dest, sizeof(dec_dest));

  // Copy encryption key file (streaming to avoid loading TB into RAM)
  FILE *src = fopen(encryption_key_file, "rb");
  FILE *dst = fopen(enc_dest, "wb");
  if (!src || !dst)
  {
    fprintf(stderr, "Error: Cannot copy encryption key file\n");
    if (src)
      fclose(src);
    if (dst)
      fclose(dst);
    return -1;
  }

  unsigned char buffer[1024 * 1024]; // 1MB buffer for streaming
  size_t bytes;
  while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
  {
    if (fwrite(buffer, 1, bytes, dst) != bytes)
    {
      fprintf(stderr, "Error: Failed to write encryption key file\n");
      fclose(src);
      fclose(dst);
      unlink(enc_dest);
      return -1;
    }
  }
  fclose(src);
  fclose(dst);

  // Copy decryption key file (streaming)
  src = fopen(decryption_key_file, "rb");
  dst = fopen(dec_dest, "wb");
  if (!src || !dst)
  {
    fprintf(stderr, "Error: Cannot copy decryption key file\n");
    if (src)
      fclose(src);
    if (dst)
      fclose(dst);
    unlink(enc_dest);
    return -1;
  }

  while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
  {
    if (fwrite(buffer, 1, bytes, dst) != bytes)
    {
      fprintf(stderr, "Error: Failed to write decryption key file\n");
      fclose(src);
      fclose(dst);
      unlink(enc_dest);
      unlink(dec_dest);
      return -1;
    }
  }
  fclose(src);
  fclose(dst);

  // Create contact with paths to key files
  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));

  // Use snprintf instead of strncpy to avoid truncation warnings
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
  int have_dir = (get_keychain_dir(g_keychain.filepath, keychain_dir, sizeof(keychain_dir)) == 0);

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
    if (load_keychain(g_keychain.filepath) == 0)
    {
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
  }

  // Delete key files
  if (g_keychain.contacts[index].EncryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].EncryptionKeyPath);
  }
  if (g_keychain.contacts[index].DecryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].DecryptionKeyPath);
  }
  if (g_keychain.contacts[index].LastMessageSent)
  {
    free(g_keychain.contacts[index].LastMessageSent);
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
  }

  if (locked)
  {
    contact_lock_release(&lock);
    // Best-effort cleanup now that nothing holds it - the contact no
    // longer exists, so there's no reuse-race concern in unlinking it.
    char lock_path[600];
    snprintf(lock_path, sizeof(lock_path), "%s/%s.lock", keychain_dir, name);
    unlink(lock_path);
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

  // Display LastMessageSent (binary data, so show size and preview)
  if (c->LastMessageSent && c->LastMessageSentSize > 0)
  {
    printf("  LastMessageSent: [binary data] (%zu bytes)\n", c->LastMessageSentSize);
  }
  else
  {
    printf("  LastMessageSent: (empty)\n");
  }

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

// Load encryption chunk
int load_encryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset,
                          unsigned char *buffer, size_t buffer_size)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  if (c->EncryptionKeyPath[0] == '\0' || c->EncryptionKeySize == 0)
  {
    fprintf(stderr, "Error: Contact '%s' has no encryption key\n", contact_name);
    return -1;
  }

  if (start_offset >= c->EncryptionKeySize)
  {
    fprintf(stderr, "Error: Start offset %zu exceeds key size %zu\n",
            start_offset, c->EncryptionKeySize);
    return -1;
  }

  size_t actual_end = (end_offset < c->EncryptionKeySize) ? end_offset : c->EncryptionKeySize;
  size_t chunk_size = actual_end - start_offset;

  if (chunk_size > buffer_size)
  {
    fprintf(stderr, "Error: Buffer too small for chunk\n");
    return -1;
  }

  // Read from file
  FILE *keyfile = fopen(c->EncryptionKeyPath, "rb");
  if (!keyfile)
  {
    fprintf(stderr, "Error: Cannot open encryption key file\n");
    return -1;
  }

  if (fseek(keyfile, start_offset, SEEK_SET) != 0)
  {
    fclose(keyfile);
    return -1;
  }

  size_t bytes_read = fread(buffer, 1, chunk_size, keyfile);
  fclose(keyfile);

  return (int)bytes_read;
}

// Load decryption chunk
int load_decryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset,
                          unsigned char *buffer, size_t buffer_size)
{
  Contact *c = find_contact(contact_name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
    return -1;
  }

  if (c->DecryptionKeyPath[0] == '\0' || c->DecryptionKeySize == 0)
  {
    fprintf(stderr, "Error: Contact '%s' has no decryption key\n", contact_name);
    return -1;
  }

  if (start_offset >= c->DecryptionKeySize)
  {
    fprintf(stderr, "Error: Start offset %zu exceeds key size %zu\n",
            start_offset, c->DecryptionKeySize);
    return -1;
  }

  size_t actual_end = (end_offset < c->DecryptionKeySize) ? end_offset : c->DecryptionKeySize;
  size_t chunk_size = actual_end - start_offset;

  if (chunk_size > buffer_size)
  {
    fprintf(stderr, "Error: Buffer too small for chunk\n");
    return -1;
  }

  // Read from file
  FILE *keyfile = fopen(c->DecryptionKeyPath, "rb");
  if (!keyfile)
  {
    fprintf(stderr, "Error: Cannot open decryption key file\n");
    return -1;
  }

  if (fseek(keyfile, start_offset, SEEK_SET) != 0)
  {
    fclose(keyfile);
    return -1;
  }

  size_t bytes_read = fread(buffer, 1, chunk_size, keyfile);
  fclose(keyfile);

  return (int)bytes_read;
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
  return 0;
}

// Encrypt with contact's encryption key
//
// Key consumption is committed in three atomic, verified steps, strictly
// in this order, before the ciphertext is ever delivered to `output`:
//   1. the finished ciphertext is staged and published as a "pending
//      artifact" tagged with the exact key range it corresponds to
//   2. the key file is truncated to remove the consumed prefix
//   3. keychain.txt is updated to match
// Only key-file-before-keychain.txt ordering is safe: if it were
// reversed, a crash between the two would leave keychain.txt believing a
// key range is spent while the key file still contains those exact
// bytes, unread and reusable - a two-time-pad break. With this ordering,
// the same crash instead leaves the key file already reduced (correct)
// and keychain.txt merely stale, which commit_reconcile() can always
// finish deterministically using the pending artifact's own filename tag.
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
  commit_reconcile(keychain_dir, contact_name, "enc", c->EncryptionKeyPath,
                    c->EncryptionKeyOffset, c->EncryptionKeySize,
                    c->EncryptedSequence, &rec);

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
    return 0;
  }

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
  unsigned char *last_msg_buffer = NULL;
  size_t last_msg_size = 0;

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
      free(last_msg_buffer);
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
      free(last_msg_buffer);
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
      free(last_msg_buffer);
      fclose(keyfile);
      commit_stage_abort(&stage);
      return -1;
    }

    // Store last message (limit to MAX_MESSAGE_LENGTH)
    if (last_msg_size < MAX_MESSAGE_LENGTH)
    {
      size_t copy_size = (last_msg_size + input_bytes <= MAX_MESSAGE_LENGTH) ? input_bytes : (MAX_MESSAGE_LENGTH - last_msg_size);
      unsigned char *new_buffer = realloc(last_msg_buffer, last_msg_size + copy_size);
      if (new_buffer)
      {
        last_msg_buffer = new_buffer;
        memcpy(last_msg_buffer + last_msg_size, chunk, copy_size);
        last_msg_size += copy_size;
      }
    }

    total_bytes += input_bytes;
  }

  fclose(keyfile);
  free(chunk);
  free(key_chunk);

  if (total_bytes == 0)
  {
    fprintf(stderr, "Error: No input data provided\n");
    free(last_msg_buffer);
    commit_stage_abort(&stage);
    return -1;
  }

  if (commit_stage_close_verified(&stage) != 0)
  {
    free(last_msg_buffer);
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
    free(last_msg_buffer);
    commit_discard_path(stage.tmp_path);
    return -1;
  }

  commit_test_crash_point("after_pending_publish");

  // Truncate consumed bytes from the key file: read what remains, stage
  // it, verify it, and only then publish it over the real key file.
  keyfile = fopen(c->EncryptionKeyPath, "rb");
  if (!keyfile || fseek(keyfile, (long)total_bytes, SEEK_SET) != 0)
  {
    fprintf(stderr, "Error: Failed to reopen encryption key for truncation\n");
    if (keyfile)
      fclose(keyfile);
    free(last_msg_buffer);
    commit_discard_path(pending_final_path);
    return -1;
  }
  size_t remaining_size = c->EncryptionKeySize - total_bytes;
  unsigned char *remaining_data = remaining_size ? malloc(remaining_size) : NULL;
  if (remaining_size && !remaining_data)
  {
    fprintf(stderr, "Error: Memory allocation failed while truncating encryption key\n");
    fclose(keyfile);
    free(last_msg_buffer);
    commit_discard_path(pending_final_path);
    return -1;
  }
  size_t read_size = remaining_size ? fread(remaining_data, 1, remaining_size, keyfile) : 0;
  fclose(keyfile);
  if (read_size != remaining_size)
  {
    fprintf(stderr, "Error: Failed to read remaining encryption key\n");
    free(remaining_data);
    free(last_msg_buffer);
    commit_discard_path(pending_final_path);
    return -1;
  }

  char key_tmp_path[560];
  snprintf(key_tmp_path, sizeof(key_tmp_path), "%s.tmp", c->EncryptionKeyPath);
  if (commit_write_verified(key_tmp_path, remaining_data, remaining_size) != 0)
  {
    free(remaining_data);
    free(last_msg_buffer);
    commit_discard_path(pending_final_path);
    return -1;
  }
  free(remaining_data);
  if (commit_publish(key_tmp_path, c->EncryptionKeyPath) != 0)
  {
    free(last_msg_buffer);
    commit_discard_path(pending_final_path);
    return -1;
  }

  commit_test_crash_point("after_key_publish");

  // Update contact metadata and commit keychain.txt (key file is already
  // committed at this point - this is the second, final half of the pair).
  if (c->LastMessageSent)
  {
    free(c->LastMessageSent);
  }
  c->LastMessageSent = last_msg_buffer;
  c->LastMessageSentSize = last_msg_size;
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
  if (get_keychain_dir(g_keychain.filepath, keychain_dir, sizeof(keychain_dir)) != 0)
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
  if (load_keychain(g_keychain.filepath) != 0)
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
  commit_reconcile(keychain_dir, contact_name, "dec", c->DecryptionKeyPath,
                    c->DecryptionKeyOffset, c->DecryptionKeySize,
                    c->DecryptedSequence, &rec);

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
    return 0;
  }

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

  // Truncate consumed bytes from the key file
  keyfile = fopen(c->DecryptionKeyPath, "rb");
  if (!keyfile || fseek(keyfile, (long)total_bytes, SEEK_SET) != 0)
  {
    fprintf(stderr, "Error: Failed to reopen decryption key for truncation\n");
    if (keyfile)
      fclose(keyfile);
    commit_discard_path(pending_final_path);
    return -1;
  }
  size_t remaining_size = c->DecryptionKeySize - total_bytes;
  unsigned char *remaining_data = remaining_size ? malloc(remaining_size) : NULL;
  if (remaining_size && !remaining_data)
  {
    fprintf(stderr, "Error: Memory allocation failed while truncating decryption key\n");
    fclose(keyfile);
    commit_discard_path(pending_final_path);
    return -1;
  }
  size_t read_size = remaining_size ? fread(remaining_data, 1, remaining_size, keyfile) : 0;
  fclose(keyfile);
  if (read_size != remaining_size)
  {
    fprintf(stderr, "Error: Failed to read remaining decryption key\n");
    free(remaining_data);
    commit_discard_path(pending_final_path);
    return -1;
  }

  char key_tmp_path[560];
  snprintf(key_tmp_path, sizeof(key_tmp_path), "%s.tmp", c->DecryptionKeyPath);
  if (commit_write_verified(key_tmp_path, remaining_data, remaining_size) != 0)
  {
    free(remaining_data);
    commit_discard_path(pending_final_path);
    return -1;
  }
  free(remaining_data);
  if (commit_publish(key_tmp_path, c->DecryptionKeyPath) != 0)
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

  // Save keychain
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
  if (get_keychain_dir(g_keychain.filepath, keychain_dir, sizeof(keychain_dir)) != 0)
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
  if (load_keychain(g_keychain.filepath) != 0)
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
