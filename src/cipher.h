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

// Delete the kept last-payload safety copies for a contact
// (<keychain_dir>/<contact>.last_sent and .last_received). Used when a
// contact is removed: removing it must take every trace of message
// content with it.
void cipher_discard_last_copies(const char *keychain_dir, const char *contact_name);

#endif // CIPHER_H
