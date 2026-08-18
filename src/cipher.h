/*****************************************************************************\
 *                                                                           *
 *   cipher.h - Encrypt/decrypt operations for OTP contacts                  *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef CIPHER_H
#define CIPHER_H

#include <stdio.h>

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

// Encryption/Decryption operations with contacts
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output);
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output);

// Delivery-confirmation gate. The wire format carries no key-range tag,
// so within one direction messages are only decryptable if they arrive in
// order, complete, exactly once - a property only the correspondents can
// verify, out of band. Before spending key on any message after the first
// in a direction, the operator is therefore asked on the terminal to
// confirm the previous message arrived intact; answering anything but
// yes cancels the operation with no key consumed. Passing 1 here (set
// from the -y/--assume-delivered flag; the OTP_ASSUME_DELIVERED
// environment variable is equivalent) records that the operator already
// confirmed out of band, so the prompt is skipped. Required for
// non-interactive use: with no terminal to ask on, the operation fails
// closed rather than assuming delivery.
void keychain_set_assume_delivered(int yes);

// --status: report one contact's per-direction state, verified from the
// disk files themselves - the key file's physical size (the authority on
// remaining key), the .meta declarations, the pending-artifact scan
// (shared with crash recovery via commit_classify) and the kept
// last-payload copies. Strictly read-only with respect to keychain state:
// it never deletes, truncates, renames or heals anything; the only files
// it can create are the ones every command creates on first touch (the
// .keychain/ directory and the contact's empty .lock file, held briefly
// for a consistent snapshot). Returns the process exit code below, or -1
// on error (unknown contact, unreadable key file).
#define KEYCHAIN_STATUS_CLEAN 0
#define KEYCHAIN_STATUS_REDELIVERY_PENDING 4
#define KEYCHAIN_STATUS_ACK_OUTSTANDING 5
#define KEYCHAIN_STATUS_ROLLED_BACK 6
int keychain_status(const char *contact_name, int porcelain);

// --recover-last: stream the kept safety copy of the last delivered
// payload (sent=1: the last encrypt's exact ciphertext; sent=0: the last
// decrypt's exact plaintext) to `output`. Read-only and idempotent: the
// copy is never deleted here - not even on a fully successful stream,
// because bytes leaving this process is not proof they were persisted or
// delivered anywhere. Only the next operation in the same direction
// removes it, when the operator confirms delivery. Returns 0 (streamed),
// KEYCHAIN_RECOVER_NO_COPY (nothing awaits confirmation), or -1 on error.
#define KEYCHAIN_RECOVER_NO_COPY 2
int keychain_recover_last(const char *contact_name, int sent, FILE *output);

// Delete the kept last-payload safety copies for a contact
// (<keychain_dir>/<contact>.last_sent and .last_received). Used when a
// contact is removed: removing it must take every trace of message
// content with it.
void cipher_discard_last_copies(const char *keychain_dir, const char *contact_name);

// Drop the consumed prefix from `key_path`: stream everything from offset
// `consumed` onward into a staging file, verify that staged copy by
// read-back, then atomically publish it over `key_path`. `direction` is
// used only in error messages. This is the same crash-safe
// stage/verify/publish primitive encrypt/decrypt use to truncate a
// contact's key file after each message; shared here so any other caller
// consuming a prefix of a file (e.g. the randomness vault) truncates it
// exactly the same way, rather than through a second, divergent code path.
int truncate_key_file(const char *direction, const char *key_path,
                      size_t consumed, size_t remaining_size);

#endif // CIPHER_H
