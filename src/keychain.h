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

// Return codes for encrypt_with_contact() / decrypt_with_contact().
//
// KEYCHAIN_REDELIVERED is deliberately distinct from KEYCHAIN_OK. When a
// previous run was interrupted after its output was committed but before
// it was delivered, the next run redelivers that recovered message and
// does NOT process the input it was given this time - the input is left
// entirely unconsumed and must be re-submitted. Reporting that as success
// would let a script believe its message had been encrypted when the
// bytes it received actually belong to the previous one.
#define KEYCHAIN_OK 0
#define KEYCHAIN_ERROR (-1)
#define KEYCHAIN_REDELIVERED 3

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

// Encryption/Decryption operations with contacts
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output);
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output);

// Helper functions
Contact *find_contact(const char *name);
void init_keychain(void);
void cleanup_keychain(void);

#endif // KEYCHAIN_H
