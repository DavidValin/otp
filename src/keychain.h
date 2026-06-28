/*****************************************************************************\
 *                                                                            *
 *   keychain.h - Keychain management for OTP contacts                       *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *                                                                            *
 \****************************************************************************/

#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <time.h>
#include <stdio.h>

#define MAX_CONTACTS 10000
#define MAX_NAME_LENGTH 256
#define MAX_KEY_SIZE 1099511627776ULL  // 1TB max key size per contact
#define MAX_MESSAGE_LENGTH 1073741824ULL  // 1GB max message length
#define MIN_RETRY_COUNT 0
#define MAX_RETRY_COUNT 25000

typedef struct {
    char Name[MAX_NAME_LENGTH];
    char EncryptionKeyPath[512];    // Path to encryption key file
    size_t EncryptionKeySize;       // Total size of encryption key file
    size_t EncryptionKeyOffset;     // How many bytes consumed
    size_t EncryptedSequence;       // Number of messages encrypted
    char DecryptionKeyPath[512];    // Path to decryption key file
    size_t DecryptionKeySize;       // Total size of decryption key file
    size_t DecryptionKeyOffset;     // How many bytes consumed
    size_t DecryptedSequence;       // Number of messages decrypted
    unsigned char *LastMessageSent; // Keep in memory (much smaller than keys)
    size_t LastMessageSentSize;
    int RetryCount;
    time_t LastMessageSentAt;
    time_t LastMessageReceivedAt;
} Contact;

typedef struct {
    Contact contacts[MAX_CONTACTS];
    int count;
    char filepath[512];
} Keychain;

// Global keychain instance
extern Keychain g_keychain;

// Keychain functions
int load_keychain(const char *file_path);
int save_keychain(const char *file_path);
int add_contact(const char *name);
int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file);
int remove_contact(const char *name);
int has_contact(const char *name);
void list_contacts(void);
void show_contact(const char *name);
int load_encryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset, unsigned char *buffer, size_t buffer_size);
int load_decryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset, unsigned char *buffer, size_t buffer_size);

// Encryption/Decryption operations with contacts
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output);
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output);

// Helper functions
Contact* find_contact(const char *name);
void init_keychain(void);
void cleanup_keychain(void);

#endif // KEYCHAIN_H
