/*****************************************************************************\
 *                                                                            *
 *   keychain.c - Keychain management for OTP contacts                       *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *                                                                            *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "keychain.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

// Platform-specific includes
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
// Windows compatibility mappings
#define mkdir(path, mode) _mkdir(path)
#define unlink(path) _unlink(path)
#define stat _stat
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
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

// Load keychain from file
int load_keychain(const char *file_path)
{
  FILE *f = fopen(file_path, "r");
  if (!f)
  {
    // If file doesn't exist, initialize empty keychain
    init_keychain();
    strncpy(g_keychain.filepath, file_path, sizeof(g_keychain.filepath) - 1);
    return 0;
  }

  cleanup_keychain();
  init_keychain();
  strncpy(g_keychain.filepath, file_path, sizeof(g_keychain.filepath) - 1);

// Use a reasonable line buffer size for parsing (keys are base64 encoded, ~1.33x original)
// 16MB buffer allows for ~12MB binary keys per line
#define LINE_BUFFER_SIZE (16 * 1024 * 1024)
  char *line = malloc(LINE_BUFFER_SIZE);
  if (!line)
  {
    fprintf(stderr, "Error: Memory allocation failed for line buffer\n");
    fclose(f);
    return -1;
  }
  while (fgets(line, LINE_BUFFER_SIZE, f))
  {
    if (line[0] == '#' || line[0] == '\n')
      continue;

    if (strncmp(line, "[CONTACT]", 9) == 0)
    {
      if (g_keychain.count >= MAX_CONTACTS)
      {
        fprintf(stderr, "Error: Maximum contacts reached\n");
        break;
      }

      Contact *c = &g_keychain.contacts[g_keychain.count];
      memset(c, 0, sizeof(Contact));

      // Read contact fields
      while (fgets(line, LINE_BUFFER_SIZE, f))
      {
        if (line[0] == '\n' || line[0] == '[')
        {
          fseek(f, -(long)strlen(line), SEEK_CUR);
          break;
        }

        char key[256];
        char *value = malloc(LINE_BUFFER_SIZE);
        if (!value)
          continue;

        // Parse key=value manually to avoid sscanf width limitations
        char *equals = strchr(line, '=');
        if (equals && sscanf(line, "%255[^=]", key) == 1)
        {
          // Copy everything after '=' to value
          strncpy(value, equals + 1, LINE_BUFFER_SIZE - 1);
          value[LINE_BUFFER_SIZE - 1] = '\0';
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

        free(value);
      }

      g_keychain.count++;
    }
  }

  free(line);
  fclose(f);
  return 0;
}

// Save keychain to file
int save_keychain(const char *file_path)
{
  FILE *f = fopen(file_path, "w");
  if (!f)
  {
    fprintf(stderr, "Error: Cannot open keychain file %s for writing: %s\n",
            file_path, strerror(errno));
    return -1;
  }

  fprintf(f, "# OTP Keychain File\n");
  fprintf(f, "# Format: key=value pairs per contact\n\n");

  for (int i = 0; i < g_keychain.count; i++)
  {
    Contact *c = &g_keychain.contacts[i];

    fprintf(f, "[CONTACT]\n");

    char escaped_name[MAX_NAME_LENGTH * 2];
    escape_string(c->Name, escaped_name, sizeof(escaped_name));
    fprintf(f, "Name=%s\n", escaped_name);

    // Save key file paths
    fprintf(f, "EncryptionKeyPath=%s\n", c->EncryptionKeyPath);
    fprintf(f, "EncryptionKeySize=%zu\n", c->EncryptionKeySize);
    fprintf(f, "EncryptionKeyOffset=%zu\n", c->EncryptionKeyOffset);
    fprintf(f, "EncryptedSequence=%zu\n", c->EncryptedSequence);

    fprintf(f, "DecryptionKeyPath=%s\n", c->DecryptionKeyPath);
    fprintf(f, "DecryptionKeySize=%zu\n", c->DecryptionKeySize);
    fprintf(f, "DecryptionKeyOffset=%zu\n", c->DecryptionKeyOffset);
    fprintf(f, "DecryptedSequence=%zu\n", c->DecryptedSequence);

    // Encode LastMessageSent as base64
    if (c->LastMessageSent && c->LastMessageSentSize > 0)
    {
      char *msg_b64 = malloc(c->LastMessageSentSize * 4 / 3 + 4);
      if (msg_b64)
      {
        base64_encode(c->LastMessageSent, c->LastMessageSentSize, msg_b64);
        fprintf(f, "LastMessageSent=%s\n", msg_b64);
        free(msg_b64);
      }
      else
      {
        fprintf(f, "LastMessageSent=\n");
      }
    }
    else
    {
      fprintf(f, "LastMessageSent=\n");
    }
    fprintf(f, "LastMessageSentSize=%zu\n", c->LastMessageSentSize);

    fprintf(f, "RetryCount=%d\n", c->RetryCount);
    fprintf(f, "LastMessageSentAt=%lld\n", (long long)c->LastMessageSentAt);
    fprintf(f, "LastMessageReceivedAt=%lld\n", (long long)c->LastMessageReceivedAt);
    fprintf(f, "\n");
  }

  fclose(f);
  strncpy(g_keychain.filepath, file_path, sizeof(g_keychain.filepath) - 1);
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

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  strncpy(c->Name, name, MAX_NAME_LENGTH - 1);
  c->RetryCount = 0;

  g_keychain.count++;

  return save_keychain(g_keychain.filepath);
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

  int result = save_keychain(g_keychain.filepath);
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

  // Shift remaining contacts
  for (int i = index; i < g_keychain.count - 1; i++)
  {
    g_keychain.contacts[i] = g_keychain.contacts[i + 1];
  }

  g_keychain.count--;

  return save_keychain(g_keychain.filepath);
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

// Encrypt with contact's encryption key
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output)
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

  // EncryptionKeySize already represents remaining bytes after truncation
  size_t available_key = c->EncryptionKeySize;
  if (available_key == 0)
  {
    fprintf(stderr, "Error: No encryption key remaining for contact '%s'\n", contact_name);
    return -1;
  }

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
      return -1;
    }

    // XOR encryption
    for (size_t i = 0; i < input_bytes; i++)
    {
      chunk[i] ^= key_chunk[i];
    }

    // Write encrypted chunk
    if (fwrite(chunk, 1, input_bytes, output) != input_bytes)
    {
      fprintf(stderr, "Error: Failed to write encrypted data\n");
      free(chunk);
      free(key_chunk);
      free(last_msg_buffer);
      fclose(keyfile);
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
    return -1;
  }

  // Truncate consumed bytes from key file
  // Read remaining key data
  keyfile = fopen(c->EncryptionKeyPath, "rb");
  if (keyfile)
  {
    // Seek past consumed bytes
    if (fseek(keyfile, total_bytes, SEEK_SET) == 0)
    {
      // Read remaining data (EncryptionKeySize already reflects current file size)
      size_t remaining_size = c->EncryptionKeySize - total_bytes;
      unsigned char *remaining_data = malloc(remaining_size);
      if (remaining_data)
      {
        size_t read_size = fread(remaining_data, 1, remaining_size, keyfile);
        fclose(keyfile);

        // Rewrite file with only remaining data
        keyfile = fopen(c->EncryptionKeyPath, "wb");
        if (keyfile)
        {
          fwrite(remaining_data, 1, read_size, keyfile);
          fclose(keyfile);
        }
        free(remaining_data);
      }
      else
      {
        fclose(keyfile);
      }
    }
    else
    {
      fclose(keyfile);
    }
  }

  // Update contact metadata
  if (c->LastMessageSent)
  {
    free(c->LastMessageSent);
  }
  c->LastMessageSent = last_msg_buffer;
  c->LastMessageSentSize = last_msg_size;
  c->EncryptedSequence++;
  c->EncryptionKeyOffset += total_bytes;
  c->EncryptionKeySize -= total_bytes; // Reduce size after truncation
  c->LastMessageSentAt = time(NULL);

  // Save keychain
  if (save_keychain(g_keychain.filepath) != 0)
  {
    fprintf(stderr, "Error: Failed to save keychain\n");
    return -1;
  }

  // Print info to stderr
  fprintf(stderr, "Used %zu bytes from encryption key for contact '%s'\n", total_bytes, contact_name);
  fprintf(stderr, "Remaining encryption key: %zu bytes\n", c->EncryptionKeySize);

  return 0;
}

// Decrypt with contact's decryption key
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output)
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

  // DecryptionKeySize already represents remaining bytes after truncation
  size_t available_key = c->DecryptionKeySize;
  if (available_key == 0)
  {
    fprintf(stderr, "Error: No decryption key remaining for contact '%s'\n", contact_name);
    return -1;
  }

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
      return -1;
    }

    // XOR decryption
    for (size_t i = 0; i < input_bytes; i++)
    {
      chunk[i] ^= key_chunk[i];
    }

    // Write decrypted chunk
    if (fwrite(chunk, 1, input_bytes, output) != input_bytes)
    {
      fprintf(stderr, "Error: Failed to write decrypted data\n");
      free(chunk);
      free(key_chunk);
      fclose(keyfile);
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
    return -1;
  }

  // Truncate consumed bytes from key file
  // Read remaining key data
  keyfile = fopen(c->DecryptionKeyPath, "rb");
  if (keyfile)
  {
    // Seek past consumed bytes
    if (fseek(keyfile, total_bytes, SEEK_SET) == 0)
    {
      // Read remaining data (DecryptionKeySize already reflects current file size)
      size_t remaining_size = c->DecryptionKeySize - total_bytes;
      unsigned char *remaining_data = malloc(remaining_size);
      if (remaining_data)
      {
        size_t read_size = fread(remaining_data, 1, remaining_size, keyfile);
        fclose(keyfile);

        // Rewrite file with only remaining data
        keyfile = fopen(c->DecryptionKeyPath, "wb");
        if (keyfile)
        {
          fwrite(remaining_data, 1, read_size, keyfile);
          fclose(keyfile);
        }
        free(remaining_data);
      }
      else
      {
        fclose(keyfile);
      }
    }
    else
    {
      fclose(keyfile);
    }
  }

  // Update contact metadata
  c->DecryptedSequence++;
  c->DecryptionKeyOffset += total_bytes;
  c->DecryptionKeySize -= total_bytes; // Reduce size after truncation
  c->LastMessageReceivedAt = time(NULL);

  // Save keychain
  if (save_keychain(g_keychain.filepath) != 0)
  {
    fprintf(stderr, "Error: Failed to save keychain\n");
    return -1;
  }

  // Print info to stderr
  fprintf(stderr, "Used %zu bytes from decryption key for contact '%s'\n", total_bytes, contact_name);
  fprintf(stderr, "Remaining decryption key: %zu bytes\n", c->DecryptionKeySize);

  return 0;
}
