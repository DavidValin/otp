/*****************************************************************************\
 *                                                                            *
 *   otp v1.1.0                                                               *
 *                                                                            *
 *    simple but effective one time pad encryption / decryption command       *
 *    that works with stdin/stdout and saves next unused key file.            *
 *    Supports key pair generation.                                           *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *   February 2 2026                                                          *
 *                                                                            *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#include <signal.h>
#ifndef _WIN32
#include <sys/file.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#endif

#include "keychain.h"
#include "platform.h"

#ifndef _WIN32
#define O_BINARY 0
#endif
#ifdef _WIN32
#include <io.h>
#include <direct.h>
#include <windows.h>
/* Map POSIX flags to MSVC equivalents */
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_RDWR
#define O_RDWR _O_RDWR
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_EXCL
#define O_EXCL _O_EXCL
#endif
#ifndef O_APPEND
#define O_APPEND _O_APPEND
#endif
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
/* flock()/LOCK_EX come from platform.h's LockFileEx-backed shim, so the
 * direct key-file mode gets the same locking guarantee on Windows as on
 * POSIX. */
#ifndef _MSC_VER
struct stat;
#endif
/* Map POSIX names to the CRT's underscore spellings */
#define close _close
#define open _open
#define fstat _fstat
#define getpid _getpid
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/* --new-key-pair writes four files; the two pads it draws from stdin are
 * each written to two of them. Close and remove every one created so
 * far: a half-written set is not usable as a pad, and leaving it behind
 * would also block the retry with EEXIST, since these are created
 * O_EXCL. remove() rather than unlink() - it is standard C and needs no
 * per-platform mapping. */
#define KEYPAIR_FILES 4
static void keypair_cleanup(FILE *files[KEYPAIR_FILES], char names[KEYPAIR_FILES][256])
{
  for (int i = 0; i < KEYPAIR_FILES; i++)
  {
    if (files[i])
    {
      fclose(files[i]);
      files[i] = NULL;
    }
    if (names[i][0])
      remove(names[i]);
  }
}

/* Stream `size` bytes from stdin into two files at once, one chunk at a
 * time. The pad is never held whole in memory: peak usage is one chunk
 * regardless of key size, so key pairs can be far larger than RAM (the
 * keychain accepts keys up to 1TB). */
#define KEYPAIR_CHUNK (1024 * 1024)
static int keypair_stream_pad(unsigned char *buf, size_t size,
                              FILE *dst1, FILE *dst2, const char *what)
{
  size_t left = size;
  while (left > 0)
  {
    size_t want = (left < KEYPAIR_CHUNK) ? left : KEYPAIR_CHUNK;
    if (fread(buf, 1, want, stdin) != want)
    {
      fprintf(stderr, "Error reading %s key chunk from stdin\n", what);
      return -1;
    }
    if (fwrite(buf, 1, want, dst1) != want || fwrite(buf, 1, want, dst2) != want)
    {
      fprintf(stderr, "Error writing %s key: %s\n", what, strerror(errno));
      return -1;
    }
    left -= want;
  }
  return 0;
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  /* Windows opens stdin/stdout in text mode by default, which corrupts
   * binary data: it rewrites \n<->\r\n and treats the first 0x1A (Ctrl-Z)
   * as end-of-file. Every byte this tool moves through the standard
   * streams is arbitrary binary - ciphertext on the way out, plaintext on
   * the way in - in both the direct key-file mode and the keychain mode
   * (which is handed these very streams as input/output). Without this a
   * message containing 0x0A, 0x0D or 0x1A would be silently mangled. The
   * file paths already use O_BINARY; this is the matching fix for the
   * streams themselves, and must run before any byte is read or written. */
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  optind = 1;

  /* **************************************************************************
   *  Handles -h (--help) command                                             *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
  {
    puts("\nThis program takes stdin, xor's it with a key file, outputs the result to stdout and creates a new file containing the part of the key file that was not used, named after the key file with a timestamp and a \".next\" suffix.\n\nUses:\n  Encrypt (using key file):\n    echo \"plain\" | otp KEY_FILE.txt > cipher.txt\n  \n  Encrypt (using keychain):\n    echo \"plain\" | otp -c <contact_name> --encrypt > cipher.txt\n  \n  Decrypt (using key file):\n    cat cipher.txt | otp KEY_FILE.txt > plain.txt\n  \n  Decrypt (using keychain):\n    cat cipher.txt | otp -c <contact_name> --decrypt > plain.txt\n  \n  Generate key pair:\n    cat /dev/urandom | otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>\n\nKeychain Commands:\n  --add-contact <name> [<enc_key_file> <dec_key_file>] (or -ac)\n\tAdd a contact to the keychain (optionally with key files)\n  --remove-contact <name> (or -rc)\tRemove a contact from the keychain\n  --has-contact <name> (or -hc)\tCheck if a contact exists\n  --list-contacts (or -lc)\t\tList all contacts\n  --show-contact <name> (or -sc)\tShow contact details\n  --contact <name> --encrypt (or -c)\tEncrypt using contact's encryption key\n  --contact <name> --decrypt (or -c)\tDecrypt using contact's decryption key\n\n");
    return 0;
  }

  /* **************************************************************************
   *  Handles keychain commands                                               *
   * *********************************************************************** */

  if (argc >= 3 && (strcmp(argv[1], "-ac") == 0 || strcmp(argv[1], "--add-contact") == 0))
  {
    load_keychain();
    int result;

    // Check if key files are provided
    if (argc >= 5)
    {
      // Add contact with keys: otp -ac <name> <enc_key_file> <dec_key_file>
      result = add_contact_with_keys(argv[2], argv[3], argv[4]);
    }
    else if (argc == 4)
    {
      /* One key file is never enough: a contact needs both an encryption
       * and a decryption key. Silently ignoring the argument here would
       * create a keyless contact and report success, leaving the user
       * believing their key was loaded. */
      fprintf(stderr, "Error: Both an encryption and a decryption key file are required\n");
      fprintf(stderr, "Usage: otp --add-contact <name> [<enc_key_file> <dec_key_file>]\n");
      cleanup_keychain();
      return 1;
    }
    else
    {
      // Add contact without keys: otp -ac <name>
      result = add_contact(argv[2]);
      if (result == 0)
      {
        printf("Contact '%s' added successfully\n", argv[2]);
      }
    }

    cleanup_keychain();
    return result == 0 ? 0 : 1;
  }

  if (argc >= 3 && (strcmp(argv[1], "-rc") == 0 || strcmp(argv[1], "--remove-contact") == 0))
  {
    load_keychain();
    int result = remove_contact(argv[2]);
    cleanup_keychain();
    if (result == 0)
    {
      printf("Contact '%s' removed successfully\n", argv[2]);
    }
    return result == 0 ? 0 : 1;
  }

  if (argc >= 3 && (strcmp(argv[1], "-hc") == 0 || strcmp(argv[1], "--has-contact") == 0))
  {
    load_keychain();
    int exists = has_contact(argv[2]);
    cleanup_keychain();
    if (exists)
    {
      printf("Contact '%s' exists\n", argv[2]);
      return 0;
    }
    else
    {
      printf("Contact '%s' does not exist\n", argv[2]);
      return 1;
    }
  }

  if (argc >= 2 && (strcmp(argv[1], "-lc") == 0 || strcmp(argv[1], "--list-contacts") == 0))
  {
    load_keychain();
    list_contacts();
    cleanup_keychain();
    return 0;
  }

  if (argc >= 3 && (strcmp(argv[1], "-sc") == 0 || strcmp(argv[1], "--show-contact") == 0))
  {
    load_keychain();
    show_contact(argv[2]);
    cleanup_keychain();
    return 0;
  }

  /* **************************************************************************
   *  Handles -c (--contact) command for encryption/decryption                *
   * *********************************************************************** */

  if (argc >= 3 && (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--contact") == 0))
  {
    if (argc < 4)
    {
      fprintf(stderr, "Error: -c option requires contact name and --encrypt or --decrypt flag\n");
      fprintf(stderr, "Usage: otp -c <contact_name> --encrypt|--decrypt\n");
      return 1;
    }
  }

  if (argc >= 4 && (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--contact") == 0))
  {
    const char *contact_name = argv[2];
    int is_encrypt = 0;
    int is_decrypt = 0;

    // Check for --encrypt or --decrypt flag
    for (int i = 3; i < argc; i++)
    {
      if (strcmp(argv[i], "--encrypt") == 0)
      {
        is_encrypt = 1;
      }
      else if (strcmp(argv[i], "--decrypt") == 0)
      {
        is_decrypt = 1;
      }
    }

    if (!is_encrypt && !is_decrypt)
    {
      fprintf(stderr, "Error: Must specify --encrypt or --decrypt with -c option\n");
      return 1;
    }

    if (is_encrypt && is_decrypt)
    {
      fprintf(stderr, "Error: Cannot specify both --encrypt and --decrypt\n");
      return 1;
    }

    load_keychain();

    int result;
    if (is_encrypt)
    {
      result = encrypt_with_contact(contact_name, stdin, stdout);
    }
    else
    {
      result = decrypt_with_contact(contact_name, stdin, stdout);
    }

    cleanup_keychain();

    /* Map to a stable exit status. KEYCHAIN_REDELIVERED gets its own,
     * non-zero code: the command produced valid output, but that output
     * is a recovered message from an interrupted earlier run and this
     * invocation's input was NOT processed. A script must be able to tell
     * that apart from success without parsing stderr. */
    if (result == KEYCHAIN_REDELIVERED)
      return KEYCHAIN_REDELIVERED;
    return result == KEYCHAIN_OK ? 0 : 1;
  }

  /* **************************************************************************
   *  Handles -nk (--new-key-pair) command                                    *
   * *********************************************************************** */

  if (argc >= 5 && (strcmp(argv[1], "-nk") == 0 || strcmp(argv[1], "--new-key-pair") == 0))
  {
    const char *size_str = argv[2];
    char *endptr = NULL;
    double size_mb = strtod(size_str, &endptr);
    if (endptr == size_str || size_mb <= 0)
    {
      fprintf(stderr, "Invalid size %s MB\n", size_str);
      return 1;
    }
    const char *part_a = argv[3];
    const char *part_b = argv[4];
    /* Range-check before converting: a size_mb larger than size_t can
     * represent makes the conversion below undefined, not merely wrong. */
    if (size_mb > (double)(SIZE_MAX / (1024 * 1024)))
    {
      fprintf(stderr, "Size too large: %s MB\n", size_str);
      return 1;
    }
    size_t size = (size_t)(size_mb * 1024 * 1024 + 0.5); // round
    if (size == 0)
    {
      fprintf(stderr, "Size too small: %s MB results in 0 bytes\n", size_str);
      return 1;
    }

    /* Part A's encryption key is Part B's decryption key and vice versa,
     * so each of the two pads read from stdin is written to two files.
     * Created in this order, all O_EXCL and 0600. */
    char names[KEYPAIR_FILES][256] = {{0}};
    FILE *files[KEYPAIR_FILES] = {0};
    snprintf(names[0], sizeof names[0], "encryption_%s.txt", part_a);
    snprintf(names[1], sizeof names[1], "decryption_%s.txt", part_a);
    snprintf(names[2], sizeof names[2], "encryption_%s.txt", part_b);
    snprintf(names[3], sizeof names[3], "decryption_%s.txt", part_b);

    for (int i = 0; i < KEYPAIR_FILES; i++)
    {
      int kfd = open(names[i], O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
      if (kfd < 0)
      {
        fprintf(stderr, "Error creating %s: %s\n", names[i], strerror(errno));
        names[i][0] = '\0'; // not ours - must not be removed
        keypair_cleanup(files, names);
        return 1;
      }
      files[i] = fdopen(kfd, "wb");
      if (!files[i])
      {
        fprintf(stderr, "Error fdopen %s: %s\n", names[i], strerror(errno));
        close(kfd);
        keypair_cleanup(files, names);
        return 1;
      }
    }

    unsigned char *buf = malloc(KEYPAIR_CHUNK);
    if (!buf)
    {
      fprintf(stderr, "Memory allocation failed\n");
      keypair_cleanup(files, names);
      return 1;
    }

    /* Pad 1 -> A's encryption key and B's decryption key.
     * Pad 2 -> A's decryption key and B's encryption key. */
    if (keypair_stream_pad(buf, size, files[0], files[3], "first") != 0 ||
        keypair_stream_pad(buf, size, files[1], files[2], "second") != 0)
    {
      free(buf);
      keypair_cleanup(files, names);
      return 1;
    }
    free(buf);

    /* fclose() reports a failed flush, which fwrite() alone cannot: a key
     * file that was silently truncated by a full disk would otherwise be
     * distributed as if complete. */
    for (int i = 0; i < KEYPAIR_FILES; i++)
    {
      if (fclose(files[i]) != 0)
      {
        fprintf(stderr, "Error writing %s: %s\n", names[i], strerror(errno));
        files[i] = NULL;
        keypair_cleanup(files, names);
        return 1;
      }
      files[i] = NULL;
    }
    return 0;
  }


  /* **************************************************************************
   *  Handles encryption / decryption via stdin + key file                    *
   * *********************************************************************** */

  // Ensure we have a key file argument for encryption/decryption
  if (argc < 2)
  {
    fprintf(stderr, "Error: No key file specified. Use -h for help.\n");
    return 1;
  }

  /* Build output name from a 1-second-resolution timestamp (no random
   * suffix); O_CREAT|O_EXCL below rejects a same-second collision instead
   * of silently overwriting it. */
  char outfileunused[256];
  time_t t = time(NULL);
  struct tm tm_struct;
#ifdef _WIN32
  localtime_s(&tm_struct, &t);
#else
  localtime_r(&t, &tm_struct);
#endif

  snprintf(outfileunused, sizeof outfileunused,
           "%s.%04d-%02d-%02d_%02d-%02d-%02d.next",
           argv[optind],
           tm_struct.tm_year + 1900, tm_struct.tm_mon + 1, tm_struct.tm_mday,
           tm_struct.tm_hour, tm_struct.tm_min, tm_struct.tm_sec);
  /* Ensure unique output file atomically (O_CREAT|O_EXCL) */
  int out_fd = open(outfileunused, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
  if (out_fd < 0)
  {
    fprintf(stderr, "Error creating output file %s: %s\n", outfileunused, strerror(errno));
    return 1;
  }

  /* Everything below shares one failure path, which removes the .next
   * file. It is created before the key file has even been opened, so
   * without that every error - an unreadable key, a short key, a failed
   * write - left behind a 0-byte or half-written successor key. That is
   * worse than leaving nothing: an empty .next file is exactly what a
   * fully consumed key looks like, and a truncated one silently discards
   * the key material it should have carried forward. */
  FILE *infile = NULL;
  FILE *unused = NULL;
  unsigned char *keybuf = NULL;
  int key_fd = -1;
  size_t key_size = 0;
  size_t used = 0;
  struct stat ks;

  unused = fdopen(out_fd, "wb");
  if (!unused)
  {
    fprintf(stderr, "Error opening output file %s: %s\n", outfileunused, strerror(errno));
    close(out_fd);
    goto fail;
  }

  /* Open and lock key file */
  key_fd = open(argv[optind], O_RDONLY | O_BINARY);
  if (key_fd < 0)
  {
    fprintf(stderr, "Error opening key file %s: %s\n", argv[optind], strerror(errno));
    goto fail;
  }
  if (flock(key_fd, LOCK_EX) < 0)
  {
    fprintf(stderr, "Error locking key file %s: %s\n", argv[optind], strerror(errno));
    close(key_fd);
    goto fail;
  }
  infile = fdopen(key_fd, "rb");
  if (!infile)
  {
    fprintf(stderr, "Error reading key file %s: %s\n", argv[optind], strerror(errno));
    close(key_fd);
    goto fail;
  }
  /* Determine key file size */
  if (fstat(key_fd, &ks) < 0)
  {
    fprintf(stderr, "Error statting key file %s: %s\n", argv[optind], strerror(errno));
    goto fail;
  }
  if (!S_ISREG(ks.st_mode))
  {
    fprintf(stderr, "%s is not a regular file\n", argv[optind]);
    goto fail;
  }
  key_size = ks.st_size;
  if (key_size == 0)
  {
    fprintf(stderr, "Key file %s is empty\n", argv[optind]);
    goto fail;
  }
  /* Read key into memory */
  keybuf = malloc(key_size);
  if (!keybuf)
  {
    fprintf(stderr, "Memory allocation failed\n");
    goto fail;
  }
  if (fread(keybuf, 1, key_size, infile) != key_size)
  {
    fprintf(stderr, "Error reading key file %s\n", argv[optind]);
    goto fail;
  }
  /* Handle empty stdin early */
  int first = fgetc(stdin);
  if (first == EOF)
  {
    /* No key was consumed, so there is no successor key to write. The
     * .next file is removed rather than left empty, which would claim
     * the opposite. */
    fprintf(stderr, "No input provided; no key consumed and no %s written.\n", outfileunused);
    free(keybuf);
    fclose(infile);
    fclose(unused);
    remove(outfileunused);
    return 0;
  }
  /* Put the byte back for normal processing */
  ungetc(first, stdin);
  /* Ignore SIGPIPE to handle closed pipes gracefully */
  signal(SIGPIPE, SIG_IGN);
  unsigned char outbyte;
  while (fread(&outbyte, 1, 1, stdin) == 1)
  {
    if (used >= key_size)
    {
      fprintf(stderr, "Error: key file %s shorter than input.\n", argv[optind]);
      goto fail;
    }
    /* Encrypt current byte using key */
    outbyte ^= keybuf[used];
    if (fwrite(&outbyte, 1, 1, stdout) != 1)
    {
      fprintf(stderr, "Error writing to stdout: %s\n", strerror(errno));
      goto fail;
    }
    used++;
  }
  if (ferror(stdin))
  {
    fprintf(stderr, "Error reading input: %s\n", strerror(errno));
    goto fail;
  }
  /* Write remaining key bytes to the .next key file */
  if (used < key_size)
  {
    if (fwrite(keybuf + used, 1, key_size - used, unused) != key_size - used)
    {
      fprintf(stderr, "Error writing remainder to %s: %s\n", outfileunused, strerror(errno));
      goto fail;
    }
  }

  free(keybuf);
  keybuf = NULL;
  fclose(infile);
  infile = NULL;

  /* fwrite() only fills a buffer; both of these are where a full disk or
   * a failing device actually reports itself. Without the checks, lost
   * ciphertext and a truncated successor key both exit 0. */
  if (fclose(unused) != 0)
  {
    fprintf(stderr, "Error writing %s: %s\n", outfileunused, strerror(errno));
    unused = NULL;
    goto fail;
  }
  unused = NULL;

  if (fflush(stdout) != 0)
  {
    fprintf(stderr, "Error writing to stdout: %s\n", strerror(errno));
    /* The .next file is already closed and correct at this point; the
     * key file is untouched, so the operation is simply retryable. */
    remove(outfileunused);
    return 1;
  }
  return 0;

fail:
  free(keybuf);
  if (infile)
    fclose(infile);
  if (unused)
    fclose(unused);
  remove(outfileunused);
  return 1;
}
