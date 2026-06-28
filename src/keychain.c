/*****************************************************************************\
 *                                                                            *
 *   keychain.c - Keychain management for OTP contacts                       *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *                                                                            *
 \****************************************************************************/

#include "keychain.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

// Global keychain instance
Keychain g_keychain = {0};

// Initialize keychain
void init_keychain(void) {
    memset(&g_keychain, 0, sizeof(Keychain));
    g_keychain.count = 0;
}

// Cleanup keychain memory
void cleanup_keychain(void) {
    for (int i = 0; i < g_keychain.count; i++) {
        if (g_keychain.contacts[i].EncryptionKey) {
            free(g_keychain.contacts[i].EncryptionKey);
            g_keychain.contacts[i].EncryptionKey = NULL;
        }
        if (g_keychain.contacts[i].DecryptionKey) {
            free(g_keychain.contacts[i].DecryptionKey);
            g_keychain.contacts[i].DecryptionKey = NULL;
        }
    }
    g_keychain.count = 0;
}

// Find a contact by name
Contact* find_contact(const char *name) {
    for (int i = 0; i < g_keychain.count; i++) {
        if (strcmp(g_keychain.contacts[i].Name, name) == 0) {
            return &g_keychain.contacts[i];
        }
    }
    return NULL;
}

// Base64 encoding helper for binary data storage
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *data, size_t input_length, char *output) {
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
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
    if (mod == 1) {
        output[j - 2] = '=';
        output[j - 1] = '=';
    } else if (mod == 2) {
        output[j - 1] = '=';
    }
    output[j] = '\0';
}

static int base64_decode_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;
    return -2;
}

static size_t base64_decode(const char *input, unsigned char *output, size_t max_output) {
    size_t i, j;
    size_t len = strlen(input);
    
    for (i = 0, j = 0; i < len && j < max_output;) {
        int a = base64_decode_value(input[i++]);
        int b = (i < len) ? base64_decode_value(input[i++]) : -1;
        int c = (i < len) ? base64_decode_value(input[i++]) : -1;
        int d = (i < len) ? base64_decode_value(input[i++]) : -1;
        
        if (a < 0 || b < 0) break;
        
        output[j++] = (a << 2) | (b >> 4);
        if (c >= 0 && j < max_output) {
            output[j++] = (b << 4) | (c >> 2);
        }
        if (d >= 0 && j < max_output) {
            output[j++] = (c << 6) | d;
        }
    }
    
    return j;
}

// Escape special characters for file storage
static void escape_string(const char *input, char *output, size_t max_output) {
    size_t i, j;
    for (i = 0, j = 0; input[i] && j < max_output - 2; i++) {
        if (input[i] == '\\' || input[i] == '\n' || input[i] == '\r') {
            output[j++] = '\\';
            if (input[i] == '\n') output[j++] = 'n';
            else if (input[i] == '\r') output[j++] = 'r';
            else output[j++] = '\\';
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

static void unescape_string(const char *input, char *output, size_t max_output) {
    size_t i, j;
    for (i = 0, j = 0; input[i] && j < max_output - 1; i++) {
        if (input[i] == '\\' && input[i+1]) {
            i++;
            if (input[i] == 'n') output[j++] = '\n';
            else if (input[i] == 'r') output[j++] = '\r';
            else output[j++] = input[i];
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

// Load keychain from file
int load_keychain(const char *file_path) {
    FILE *f = fopen(file_path, "r");
    if (!f) {
        // If file doesn't exist, initialize empty keychain
        init_keychain();
        strncpy(g_keychain.filepath, file_path, sizeof(g_keychain.filepath) - 1);
        return 0;
    }
    
    cleanup_keychain();
    init_keychain();
    strncpy(g_keychain.filepath, file_path, sizeof(g_keychain.filepath) - 1);
    
    char line[MAX_KEY_SIZE * 2 + 1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        if (strncmp(line, "[CONTACT]", 9) == 0) {
            if (g_keychain.count >= MAX_CONTACTS) {
                fprintf(stderr, "Error: Maximum contacts reached\n");
                break;
            }
            
            Contact *c = &g_keychain.contacts[g_keychain.count];
            memset(c, 0, sizeof(Contact));
            
            // Read contact fields
            while (fgets(line, sizeof(line), f)) {
                if (line[0] == '\n' || line[0] == '[') {
                    fseek(f, -(long)strlen(line), SEEK_CUR);
                    break;
                }
                
                char key[256], value[MAX_KEY_SIZE * 2];
                if (sscanf(line, "%255[^=]=%[^\n]", key, value) == 2) {
                    if (strcmp(key, "Name") == 0) {
                        unescape_string(value, c->Name, MAX_NAME_LENGTH);
                    } else if (strcmp(key, "EncryptionKey") == 0) {
                        c->EncryptionKey = malloc(MAX_KEY_SIZE);
                        c->EncryptionKeySize = base64_decode(value, c->EncryptionKey, MAX_KEY_SIZE);
                    } else if (strcmp(key, "EncryptionKeyOffset") == 0) {
                        c->EncryptionKeyOffset = (size_t)atoll(value);
                    } else if (strcmp(key, "Sequence") == 0) {
                        c->Sequence = (size_t)atoll(value);
                    } else if (strcmp(key, "DecryptionKey") == 0) {
                        c->DecryptionKey = malloc(MAX_KEY_SIZE);
                        c->DecryptionKeySize = base64_decode(value, c->DecryptionKey, MAX_KEY_SIZE);
                    } else if (strcmp(key, "DecryptionKeyOffset") == 0) {
                        c->DecryptionKeyOffset = (size_t)atoll(value);
                    } else if (strcmp(key, "LastMessageSent") == 0) {
                        unescape_string(value, c->LastMessageSent, MAX_MESSAGE_LENGTH);
                    } else if (strcmp(key, "RetryCount") == 0) {
                        c->RetryCount = atoi(value);
                        if (c->RetryCount < MIN_RETRY_COUNT) c->RetryCount = MIN_RETRY_COUNT;
                        if (c->RetryCount > MAX_RETRY_COUNT) c->RetryCount = MAX_RETRY_COUNT;
                    } else if (strcmp(key, "LastMessageSentAt") == 0) {
                        c->LastMessageSentAt = (time_t)atoll(value);
                    } else if (strcmp(key, "LastMessageReceivedAt") == 0) {
                        c->LastMessageReceivedAt = (time_t)atoll(value);
                    }
                }
            }
            
            g_keychain.count++;
        }
    }
    
    fclose(f);
    return 0;
}

// Save keychain to file
int save_keychain(const char *file_path) {
    FILE *f = fopen(file_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open keychain file %s for writing: %s\n", 
                file_path, strerror(errno));
        return -1;
    }
    
    fprintf(f, "# OTP Keychain File\n");
    fprintf(f, "# Format: key=value pairs per contact\n\n");
    
    for (int i = 0; i < g_keychain.count; i++) {
        Contact *c = &g_keychain.contacts[i];
        
        fprintf(f, "[CONTACT]\n");
        
        char escaped_name[MAX_NAME_LENGTH * 2];
        escape_string(c->Name, escaped_name, sizeof(escaped_name));
        fprintf(f, "Name=%s\n", escaped_name);
        
        // Encode encryption key
        if (c->EncryptionKey && c->EncryptionKeySize > 0) {
            char *enc_key_b64 = malloc(c->EncryptionKeySize * 4 / 3 + 4);
            base64_encode(c->EncryptionKey, c->EncryptionKeySize, enc_key_b64);
            fprintf(f, "EncryptionKey=%s\n", enc_key_b64);
            free(enc_key_b64);
        } else {
            fprintf(f, "EncryptionKey=\n");
        }
        
        fprintf(f, "EncryptionKeyOffset=%zu\n", c->EncryptionKeyOffset);
        fprintf(f, "Sequence=%zu\n", c->Sequence);
        
        // Encode decryption key
        if (c->DecryptionKey && c->DecryptionKeySize > 0) {
            char *dec_key_b64 = malloc(c->DecryptionKeySize * 4 / 3 + 4);
            base64_encode(c->DecryptionKey, c->DecryptionKeySize, dec_key_b64);
            fprintf(f, "DecryptionKey=%s\n", dec_key_b64);
            free(dec_key_b64);
        } else {
            fprintf(f, "DecryptionKey=\n");
        }
        
        fprintf(f, "DecryptionKeyOffset=%zu\n", c->DecryptionKeyOffset);
        
        char escaped_msg[MAX_MESSAGE_LENGTH * 2];
        escape_string(c->LastMessageSent, escaped_msg, sizeof(escaped_msg));
        fprintf(f, "LastMessageSent=%s\n", escaped_msg);
        
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
int add_contact(const char *name) {
    if (g_keychain.count >= MAX_CONTACTS) {
        fprintf(stderr, "Error: Maximum contacts reached\n");
        return -1;
    }
    
    if (find_contact(name)) {
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
int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file) {
    if (g_keychain.count >= MAX_CONTACTS) {
        fprintf(stderr, "Error: Maximum contacts reached\n");
        return -1;
    }
    
    if (find_contact(name)) {
        fprintf(stderr, "Error: Contact '%s' already exists\n", name);
        return -1;
    }
    
    // Read encryption key file
    FILE *enc_file = fopen(encryption_key_file, "rb");
    if (!enc_file) {
        fprintf(stderr, "Error: Cannot open encryption key file '%s': %s\n", 
                encryption_key_file, strerror(errno));
        return -1;
    }
    
    // Get encryption key size
    fseek(enc_file, 0, SEEK_END);
    size_t enc_size = ftell(enc_file);
    fseek(enc_file, 0, SEEK_SET);
    
    if (enc_size > MAX_KEY_SIZE) {
        fprintf(stderr, "Error: Encryption key file too large (max %d bytes)\n", MAX_KEY_SIZE);
        fclose(enc_file);
        return -1;
    }
    
    if (enc_size == 0) {
        fprintf(stderr, "Error: Encryption key file is empty\n");
        fclose(enc_file);
        return -1;
    }
    
    unsigned char *enc_key = malloc(enc_size);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(enc_file);
        return -1;
    }
    
    if (fread(enc_key, 1, enc_size, enc_file) != enc_size) {
        fprintf(stderr, "Error: Failed to read encryption key file\n");
        free(enc_key);
        fclose(enc_file);
        return -1;
    }
    fclose(enc_file);
    
    // Read decryption key file
    FILE *dec_file = fopen(decryption_key_file, "rb");
    if (!dec_file) {
        fprintf(stderr, "Error: Cannot open decryption key file '%s': %s\n", 
                decryption_key_file, strerror(errno));
        free(enc_key);
        return -1;
    }
    
    // Get decryption key size
    fseek(dec_file, 0, SEEK_END);
    size_t dec_size = ftell(dec_file);
    fseek(dec_file, 0, SEEK_SET);
    
    if (dec_size > MAX_KEY_SIZE) {
        fprintf(stderr, "Error: Decryption key file too large (max %d bytes)\n", MAX_KEY_SIZE);
        free(enc_key);
        fclose(dec_file);
        return -1;
    }
    
    if (dec_size == 0) {
        fprintf(stderr, "Error: Decryption key file is empty\n");
        free(enc_key);
        fclose(dec_file);
        return -1;
    }
    
    unsigned char *dec_key = malloc(dec_size);
    if (!dec_key) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(enc_key);
        fclose(dec_file);
        return -1;
    }
    
    if (fread(dec_key, 1, dec_size, dec_file) != dec_size) {
        fprintf(stderr, "Error: Failed to read decryption key file\n");
        free(enc_key);
        free(dec_key);
        fclose(dec_file);
        return -1;
    }
    fclose(dec_file);
    
    // Create contact
    Contact *c = &g_keychain.contacts[g_keychain.count];
    memset(c, 0, sizeof(Contact));
    strncpy(c->Name, name, MAX_NAME_LENGTH - 1);
    c->EncryptionKey = enc_key;
    c->EncryptionKeySize = enc_size;
    c->EncryptionKeyOffset = 0;
    c->DecryptionKey = dec_key;
    c->DecryptionKeySize = dec_size;
    c->DecryptionKeyOffset = 0;
    c->Sequence = 0;
    c->RetryCount = 0;
    c->LastMessageSentAt = 0;
    c->LastMessageReceivedAt = 0;
    
    g_keychain.count++;
    
    int result = save_keychain(g_keychain.filepath);
    if (result == 0) {
        printf("Contact '%s' added with keys:\n", name);
        printf("  Encryption key: %zu bytes from %s\n", enc_size, encryption_key_file);
        printf("  Decryption key: %zu bytes from %s\n", dec_size, decryption_key_file);
    }
    
    return result;
}

// Remove a contact
int remove_contact(const char *name) {
    int index = -1;
    for (int i = 0; i < g_keychain.count; i++) {
        if (strcmp(g_keychain.contacts[i].Name, name) == 0) {
            index = i;
            break;
        }
    }
    
    if (index == -1) {
        fprintf(stderr, "Error: Contact '%s' not found\n", name);
        return -1;
    }
    
    // Free memory
    if (g_keychain.contacts[index].EncryptionKey) {
        free(g_keychain.contacts[index].EncryptionKey);
    }
    if (g_keychain.contacts[index].DecryptionKey) {
        free(g_keychain.contacts[index].DecryptionKey);
    }
    
    // Shift remaining contacts
    for (int i = index; i < g_keychain.count - 1; i++) {
        g_keychain.contacts[i] = g_keychain.contacts[i + 1];
    }
    
    g_keychain.count--;
    
    return save_keychain(g_keychain.filepath);
}

// Check if contact exists
int has_contact(const char *name) {
    return find_contact(name) != NULL;
}

// List all contacts
void list_contacts(void) {
    if (g_keychain.count == 0) {
        printf("No contacts in keychain\n");
        return;
    }
    
    printf("Contacts (%d):\n", g_keychain.count);
    for (int i = 0; i < g_keychain.count; i++) {
        printf("  - %s\n", g_keychain.contacts[i].Name);
    }
}

// Show contact details
void show_contact(const char *name) {
    Contact *c = find_contact(name);
    if (!c) {
        fprintf(stderr, "Error: Contact '%s' not found\n", name);
        return;
    }
    
    printf("\nContact: %s\n", c->Name);
    printf("  EncryptionKey: ******* (%zu bytes)\n", c->EncryptionKeySize);
    printf("  EncryptionKeyOffset: %zu\n", c->EncryptionKeyOffset);
    printf("  Sequence: %zu\n", c->Sequence);
    printf("  DecryptionKey: ******* (%zu bytes)\n", c->DecryptionKeySize);
    printf("  DecryptionKeyOffset: %zu\n", c->DecryptionKeyOffset);
    printf("  LastMessageSent: %s\n", c->LastMessageSent);
    printf("  RetryCount: %d\n", c->RetryCount);
    
    if (c->LastMessageSentAt > 0) {
        printf("  LastMessageSentAt: %s", ctime(&c->LastMessageSentAt));
    } else {
        printf("  LastMessageSentAt: never\n");
    }
    
    if (c->LastMessageReceivedAt > 0) {
        printf("  LastMessageReceivedAt: %s", ctime(&c->LastMessageReceivedAt));
    } else {
        printf("  LastMessageReceivedAt: never\n");
    }
    printf("\n");
}

// Load encryption chunk
int load_encryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset, 
                          unsigned char *buffer, size_t buffer_size) {
    Contact *c = find_contact(contact_name);
    if (!c) {
        fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
        return -1;
    }
    
    if (!c->EncryptionKey || c->EncryptionKeySize == 0) {
        fprintf(stderr, "Error: Contact '%s' has no encryption key\n", contact_name);
        return -1;
    }
    
    if (start_offset >= c->EncryptionKeySize) {
        fprintf(stderr, "Error: Start offset %zu exceeds key size %zu\n", 
                start_offset, c->EncryptionKeySize);
        return -1;
    }
    
    size_t actual_end = (end_offset < c->EncryptionKeySize) ? end_offset : c->EncryptionKeySize;
    size_t chunk_size = actual_end - start_offset;
    
    if (chunk_size > buffer_size) {
        fprintf(stderr, "Error: Buffer too small for chunk\n");
        return -1;
    }
    
    memcpy(buffer, c->EncryptionKey + start_offset, chunk_size);
    return (int)chunk_size;
}

// Load decryption chunk
int load_decryption_chunk(const char *contact_name, size_t start_offset, size_t end_offset, 
                          unsigned char *buffer, size_t buffer_size) {
    Contact *c = find_contact(contact_name);
    if (!c) {
        fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
        return -1;
    }
    
    if (!c->DecryptionKey || c->DecryptionKeySize == 0) {
        fprintf(stderr, "Error: Contact '%s' has no decryption key\n", contact_name);
        return -1;
    }
    
    if (start_offset >= c->DecryptionKeySize) {
        fprintf(stderr, "Error: Start offset %zu exceeds key size %zu\n", 
                start_offset, c->DecryptionKeySize);
        return -1;
    }
    
    size_t actual_end = (end_offset < c->DecryptionKeySize) ? end_offset : c->DecryptionKeySize;
    size_t chunk_size = actual_end - start_offset;
    
    if (chunk_size > buffer_size) {
        fprintf(stderr, "Error: Buffer too small for chunk\n");
        return -1;
    }
    
    memcpy(buffer, c->DecryptionKey + start_offset, chunk_size);
    return (int)chunk_size;
}

// Encrypt with contact's encryption key
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output) {
    Contact *c = find_contact(contact_name);
    if (!c) {
        fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
        return -1;
    }
    
    if (!c->EncryptionKey || c->EncryptionKeySize == 0) {
        fprintf(stderr, "Error: Contact '%s' has no encryption key\n", contact_name);
        return -1;
    }
    
    // Read input data to determine size - allocate one extra byte to check for overflow
    unsigned char *input_buffer = malloc(c->EncryptionKeySize + 1);
    if (!input_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    size_t bytes_read = fread(input_buffer, 1, c->EncryptionKeySize + 1, input);
    
    if (bytes_read == 0) {
        fprintf(stderr, "Error: No input data provided\n");
        free(input_buffer);
        return -1;
    }
    
    // Check if we have enough key material
    if (bytes_read > c->EncryptionKeySize) {
        fprintf(stderr, "Error: Message size (%zu bytes) exceeds available encryption key size (%zu bytes) for contact '%s'\n",
                bytes_read, c->EncryptionKeySize, contact_name);
        free(input_buffer);
        return -1;
    }
    
    // Perform XOR encryption
    unsigned char *output_buffer = malloc(bytes_read);
    if (!output_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(input_buffer);
        return -1;
    }
    
    for (size_t i = 0; i < bytes_read; i++) {
        output_buffer[i] = input_buffer[i] ^ c->EncryptionKey[i];
    }
    
    // Write encrypted data to output
    if (fwrite(output_buffer, 1, bytes_read, output) != bytes_read) {
        fprintf(stderr, "Error: Failed to write encrypted data to output\n");
        free(input_buffer);
        free(output_buffer);
        return -1;
    }
    
    // Store cipher text in LastMessageSent (truncate if needed)
    size_t msg_copy_size = (bytes_read < MAX_MESSAGE_LENGTH - 1) ? bytes_read : (MAX_MESSAGE_LENGTH - 1);
    memcpy(c->LastMessageSent, output_buffer, msg_copy_size);
    c->LastMessageSent[msg_copy_size] = '\0';
    
    // Update contact metadata
    c->Sequence++;
    c->EncryptionKeyOffset += bytes_read;
    c->LastMessageSentAt = time(NULL);
    
    // Update encryption key - keep only unused portion
    size_t remaining_key_size = c->EncryptionKeySize - bytes_read;
    if (remaining_key_size > 0) {
        unsigned char *new_key = malloc(remaining_key_size);
        if (!new_key) {
            fprintf(stderr, "Error: Memory allocation failed for new key\n");
            free(input_buffer);
            free(output_buffer);
            return -1;
        }
        memcpy(new_key, c->EncryptionKey + bytes_read, remaining_key_size);
        free(c->EncryptionKey);
        c->EncryptionKey = new_key;
        c->EncryptionKeySize = remaining_key_size;
    } else {
        // Key is completely used
        free(c->EncryptionKey);
        c->EncryptionKey = NULL;
        c->EncryptionKeySize = 0;
    }
    
    // Save keychain
    int save_result = save_keychain(g_keychain.filepath);
    if (save_result != 0) {
        fprintf(stderr, "Error: Failed to save keychain\n");
        free(input_buffer);
        free(output_buffer);
        return -1;
    }
    
    // Print info to stderr
    fprintf(stderr, "Used %zu bytes from encryption key for contact '%s'\n", bytes_read, contact_name);
    fprintf(stderr, "Remaining encryption key: %zu bytes\n", remaining_key_size);
    
    free(input_buffer);
    free(output_buffer);
    return 0;
}

// Decrypt with contact's decryption key
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output) {
    Contact *c = find_contact(contact_name);
    if (!c) {
        fprintf(stderr, "Error: Contact '%s' not found\n", contact_name);
        return -1;
    }
    
    if (!c->DecryptionKey || c->DecryptionKeySize == 0) {
        fprintf(stderr, "Error: Contact '%s' has no decryption key\n", contact_name);
        return -1;
    }
    
    // Read input data to determine size - allocate one extra byte to check for overflow
    unsigned char *input_buffer = malloc(c->DecryptionKeySize + 1);
    if (!input_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }
    
    size_t bytes_read = fread(input_buffer, 1, c->DecryptionKeySize + 1, input);
    
    if (bytes_read == 0) {
        fprintf(stderr, "Error: No input data provided\n");
        free(input_buffer);
        return -1;
    }
    
    // Check if we have enough key material
    if (bytes_read > c->DecryptionKeySize) {
        fprintf(stderr, "Error: Message size (%zu bytes) exceeds available decryption key size (%zu bytes) for contact '%s'\n",
                bytes_read, c->DecryptionKeySize, contact_name);
        free(input_buffer);
        return -1;
    }
    
    // Perform XOR decryption
    unsigned char *output_buffer = malloc(bytes_read);
    if (!output_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(input_buffer);
        return -1;
    }
    
    for (size_t i = 0; i < bytes_read; i++) {
        output_buffer[i] = input_buffer[i] ^ c->DecryptionKey[i];
    }
    
    // Write decrypted data to output
    if (fwrite(output_buffer, 1, bytes_read, output) != bytes_read) {
        fprintf(stderr, "Error: Failed to write decrypted data to output\n");
        free(input_buffer);
        free(output_buffer);
        return -1;
    }
    
    // Update contact metadata (no LastMessageSent update for decryption)
    c->Sequence++;
    c->DecryptionKeyOffset += bytes_read;
    c->LastMessageReceivedAt = time(NULL);
    
    // Update decryption key - keep only unused portion
    size_t remaining_key_size = c->DecryptionKeySize - bytes_read;
    if (remaining_key_size > 0) {
        unsigned char *new_key = malloc(remaining_key_size);
        if (!new_key) {
            fprintf(stderr, "Error: Memory allocation failed for new key\n");
            free(input_buffer);
            free(output_buffer);
            return -1;
        }
        memcpy(new_key, c->DecryptionKey + bytes_read, remaining_key_size);
        free(c->DecryptionKey);
        c->DecryptionKey = new_key;
        c->DecryptionKeySize = remaining_key_size;
    } else {
        // Key is completely used
        free(c->DecryptionKey);
        c->DecryptionKey = NULL;
        c->DecryptionKeySize = 0;
    }
    
    // Save keychain
    int save_result = save_keychain(g_keychain.filepath);
    if (save_result != 0) {
        fprintf(stderr, "Error: Failed to save keychain\n");
        free(input_buffer);
        free(output_buffer);
        return -1;
    }
    
    // Print info to stderr
    fprintf(stderr, "Used %zu bytes from decryption key for contact '%s'\n", bytes_read, contact_name);
    fprintf(stderr, "Remaining decryption key: %zu bytes\n", remaining_key_size);
    
    free(input_buffer);
    free(output_buffer);
    return 0;
}
