/*****************************************************************************\
 *                                                                           *
 *   keychain.h - Keychain management for OTP contacts                       *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <time.h>
#include <stdio.h>

#define MAX_CONTACTS 10000
#define MAX_NAME_LENGTH 256
#define MAX_KEY_SIZE 1099511627776ULL // 1TB max key size per contact
#define MIN_RETRY_COUNT 0
#define MAX_RETRY_COUNT 25000

typedef struct
{
  char Name[MAX_NAME_LENGTH];
  char EncryptionKeyPath[512];    // Path to encryption key file
  size_t EncryptionKeySize;       // Total size of encryption key file
  size_t EncryptionKeyOffset;     // How many bytes consumed
  size_t EncryptedSequence;       // Number of messages encrypted
  char DecryptionKeyPath[512];    // Path to decryption key file
  size_t DecryptionKeySize;       // Total size of decryption key file
  size_t DecryptionKeyOffset;     // How many bytes consumed
  size_t DecryptedSequence;       // Number of messages decrypted
  int RetryCount;
  time_t LastMessageSentAt;
  time_t LastMessageReceivedAt;
} Contact;

typedef struct
{
  Contact contacts[MAX_CONTACTS];
  int count;
} Keychain;

// Global keychain instance
extern Keychain g_keychain;

// Keychain functions
//
// There is no save_keychain(): each contact's metadata is persisted to
// its own file (<keychain_dir>/<name>.meta) internally by the functions
// below as they modify that contact, so two different contacts can never
// collide on a shared save. See the "Per-contact metadata files" section
// of README.md.
int load_keychain(void);
int add_contact(const char *name);
int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file);
int remove_contact(const char *name);
int has_contact(const char *name);
void list_contacts(void);
void show_contact(const char *name);

// Helper functions
Contact *find_contact(const char *name);
void init_keychain(void);
void cleanup_keychain(void);

// Shared with cipher.c, which owns encrypt_with_contact() /
// decrypt_with_contact() (declared in cipher.h) but commits its key
// consumption through the keychain's own primitives:
//
// Resolve (and create if missing) the keychain directory.
int get_keychain_dir(char *dir_path, size_t dir_path_size);
// Append `size` bytes of randomness read from stdin to the keychain's
// randomness vault (<keychain_dir>/_randomness), creating it (mode 0600)
// on first use. Not tied to any contact, but still flock()'d
// (<keychain_dir>/_randomness.lock) against concurrent appends, and the
// incoming bytes are staged and read-back verified before the vault
// itself is ever touched - a short read from stdin leaves it unchanged.
// On success, *out_total_size (if non-NULL) receives the vault's total
// size after this call.
int add_rand_to_vault(size_t size, size_t *out_total_size);
// Persist one contact's metadata atomically and verified.
int save_contact_meta(const char *keychain_dir, Contact *c);
// Record a key file's head in the spent-heads registry; direction is
// "enc" or "dec". Fails closed - a non-zero return must abort the
// operation before any key material is spent.
int spent_head_record(const char *keychain_dir, const char *direction,
                      const char *key_path);

#endif // KEYCHAIN_H
