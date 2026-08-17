/*****************************************************************************\
 *                                                                            *
 *   otp v1.3.1                                                               *
 *                                                                            *
 *    simple but effective one time pad encryption / decryption command       *
 *    that works with stdin/stdout, managing contacts and key material        *
 *    through a keychain. Supports key pair generation.                       *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *   August 17 2026                                                           *
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
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#endif

#include "keychain.h"
#include "cipher.h"
#include "compat.h"

#ifndef _WIN32
#define O_BINARY 0
#endif
#ifdef _WIN32
#include <io.h>
#include <direct.h>
#include <windows.h>
/* Map POSIX flags to MSVC equivalents */
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_EXCL
#define O_EXCL _O_EXCL
#endif
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
/* Map POSIX names to the CRT's underscore spellings. */
#define close _close
#define open _open
#define mkdir(path, mode) _mkdir(path)
#define rmdir _rmdir
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/* Does a standard stream refer to an interactive terminal? stdin: used
 * by --new-key-pair to fail fast instead of blocking on a stdin nobody
 * is feeding. stdout: gates the generation progress spinner and ANSI
 * colors, so redirected or piped output stays plain text. */
#ifdef _WIN32
#define otp_isatty(f) _isatty(_fileno(f))
#else
#define otp_isatty(f) isatty(fileno(f))
#endif
#define otp_stdin_is_tty() otp_isatty(stdin)
#define otp_stdout_is_tty() otp_isatty(stdout)

/* ANSI colors for the key-pair generation report; emitted only when
 * stdout is a terminal. */
#define OTP_GREEN "\x1b[32m"
#define OTP_YELLOW "\x1b[33m"
#define OTP_RESET "\x1b[0m"

/* --new-key-pair writes four files, two per party, each pair inside its
 * own <name>_keys/ directory; the two pads it draws from stdin are each
 * written to two of the files. Close and remove every file created so
 * far: a half-written set is not usable as a pad, and leaving it behind
 * would also block the retry with EEXIST, since these are created
 * O_EXCL. remove() rather than unlink() - it is standard C and needs no
 * per-platform mapping. */
#define KEYPAIR_FILES 4
#define KEYPAIR_DIRS 2
static void keypair_cleanup(FILE *files[KEYPAIR_FILES], char names[KEYPAIR_FILES][256],
                            char dirs[KEYPAIR_DIRS][256])
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
  /* Only directories this run created are recorded in dirs[], so a
   * pre-existing <name>_keys/ the user already had is never deleted.
   * rmdir() also refuses a non-empty directory, so any file we did not
   * create (and therefore did not remove above) keeps its directory. */
  for (int i = 0; i < KEYPAIR_DIRS; i++)
  {
    if (dirs[i][0])
      rmdir(dirs[i]);
  }
}

/* Progress spinner shown while the pads stream from stdin, so a long
 * generation visibly distinguishes "working" from "hung". Active only
 * when the frame index is >= 0 (set by the caller when stdout is a
 * terminal); one tick per streamed chunk, each overwriting the previous
 * frame with a backspace. */
static int keypair_spinner_frame = -1;
static void keypair_spinner_tick(void)
{
  static const char frames[] = "|/-\\";
  if (keypair_spinner_frame < 0)
    return;
  printf("\b%c", frames[keypair_spinner_frame++ & 3]);
  fflush(stdout);
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
    keypair_spinner_tick();
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
   * the way in - and the keychain encrypt/decrypt path is handed these
   * very streams as input/output. Without this a message containing 0x0A,
   * 0x0D or 0x1A would be silently mangled. The file paths already use
   * O_BINARY; this is the matching fix for the streams themselves, and
   * must run before any byte is read or written. */
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  /* **************************************************************************
   *  Handles -h (--help) command                                             *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
  {
    puts("\n\n otp 1.3.1 - www.davidvalin.com\n\nThis program takes stdin, xor's it with one-time-pad key material held in a keychain of contacts, and outputs the result to stdout. Consumed key material is destroyed automatically so it can never be reused.\n\nUses:\n  Encrypt (using keychain):\n    echo \"plain\" | otp -c <contact_name> --encrypt > cipher.txt\n  \n  Decrypt (using keychain):\n    cat cipher.txt | otp -c <contact_name> --decrypt > plain.txt\n  \n  Generate key pair:\n    cat /dev/urandom | otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>\n    Writes each party's keys into its own directory, named for the correspondent:\n      <part_a_name>_keys/encryption_for_<part_b_name>.key and <part_a_name>_keys/decryption_from_<part_b_name>.key\n      <part_b_name>_keys/encryption_for_<part_a_name>.key and <part_b_name>_keys/decryption_from_<part_a_name>.key\n\nKeychain Commands:\n  --add-contact <name> [<enc_key_file> <dec_key_file>] (or -ac)\n\tAdd a contact to the keychain (optionally with key files)\n  --remove-contact <name> (or -rc)\tRemove a contact from the keychain\n  --has-contact <name> (or -hc)\tCheck if a contact exists\n  --list-contacts (or -lc)\t\tList all contacts\n  --show-contact <name> (or -sc)\tShow contact details\n  --contact <name> --encrypt (or -c)\tEncrypt using contact's encryption key\n  --contact <name> --decrypt (or -c)\tDecrypt using contact's decryption key\n  -y (or --assume-delivered)\t\tSkip the delivery-confirmation prompt. Ciphertext carries no key-range tag, so each direction's messages must be processed in the exact order sent, complete, exactly once; before spending key on any message after the first, otp asks on the terminal whether the previous message arrived intact, and cancels (keys untouched) unless answered yes. Pass -y (or set OTP_ASSUME_DELIVERED=1) after confirming out of band - required when no terminal is available.\n\nSafety copies:\n  Each keychain encrypt/decrypt keeps an exact copy of its stdout payload at .keychain/<contact>.last_sent (ciphertext) or .keychain/<contact>.last_received (plaintext), so a forgotten redirect cannot lose a message whose key bytes are already destroyed. The copy is removed automatically (no manual cleanup needed) when the next operation in that direction confirms delivery; if delivery is rejected, otp offers to recover the copy to a file.\n\n");
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
      fprintf(stderr, "Usage: otp -c <contact_name> --encrypt|--decrypt [-y|--assume-delivered]\n");
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
      else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--assume-delivered") == 0)
      {
        /* The operator confirmed out of band that the previous message in
         * this direction arrived intact, so the interactive
         * delivery-confirmation prompt is skipped. Required for scripts:
         * with no terminal to ask on, the gate fails closed. */
        keychain_set_assume_delivered(1);
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
    /* Key material is read from stdin, so a terminal there means no
     * randomness source was piped in: the command would silently block
     * waiting for megabytes of typed input - and keyboard input is not
     * pad-quality randomness anyway. Checked before anything else, so a
     * refused run creates no directory and no file. */
    if (otp_stdin_is_tty())
    {
      fprintf(stderr,
              "Error: --new-key-pair reads key material from stdin, but stdin is a "
              "terminal.\nPipe in a randomness source, e.g.:\n"
              "  cat /dev/urandom | otp --new-key-pair %s %s %s\n",
              argv[2], argv[3], argv[4]);
      return 1;
    }

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
     * Each party gets its own directory, <name>_keys/, holding that
     * party's encryption_for_<peer>.key and decryption_from_<peer>.key -
     * the pair of files that party receives, ready to hand over as one
     * unit, each named for the correspondent it is used with. Directories
     * are created 0700 (a pre-existing one is reused); files in this
     * order, all O_EXCL and 0600. */
    char names[KEYPAIR_FILES][256] = {{0}};
    FILE *files[KEYPAIR_FILES] = {0};
    char dirs[KEYPAIR_DIRS][256] = {{0}}; /* only directories created by this run */
    const char *parts[KEYPAIR_DIRS] = {part_a, part_b};

    for (int i = 0; i < KEYPAIR_DIRS; i++)
    {
      char dir[256];
      if (snprintf(dir, sizeof dir, "%s_keys", parts[i]) >= (int)sizeof dir)
      {
        fprintf(stderr, "Error: name %s is too long\n", parts[i]);
        keypair_cleanup(files, names, dirs);
        return 1;
      }
      if (mkdir(dir, 0700) == 0)
        memcpy(dirs[i], dir, sizeof dir);
      else if (errno != EEXIST)
      {
        fprintf(stderr, "Error creating directory %s: %s\n", dir, strerror(errno));
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    /* Each file is named for the correspondent it is used with, so both
     * party names appear in every path; check truncation so a truncated
     * path can never be created or removed. */
    if (snprintf(names[0], sizeof names[0], "%s_keys/encryption_for_%s.key", part_a, part_b) >= (int)sizeof names[0] ||
        snprintf(names[1], sizeof names[1], "%s_keys/decryption_from_%s.key", part_a, part_b) >= (int)sizeof names[1] ||
        snprintf(names[2], sizeof names[2], "%s_keys/encryption_for_%s.key", part_b, part_a) >= (int)sizeof names[2] ||
        snprintf(names[3], sizeof names[3], "%s_keys/decryption_from_%s.key", part_b, part_a) >= (int)sizeof names[3])
    {
      fprintf(stderr, "Error: key file path too long\n");
      memset(names, 0, sizeof names); // truncated paths are not ours to remove
      keypair_cleanup(files, names, dirs);
      return 1;
    }

    for (int i = 0; i < KEYPAIR_FILES; i++)
    {
      int kfd = open(names[i], O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
      if (kfd < 0)
      {
        fprintf(stderr, "Error creating %s: %s\n", names[i], strerror(errno));
        /* Neither this file nor the ones after it were created by this
         * run; a pre-existing file at any of those paths is not ours to
         * remove. */
        for (int j = i; j < KEYPAIR_FILES; j++)
          names[j][0] = '\0';
        keypair_cleanup(files, names, dirs);
        return 1;
      }
      files[i] = fdopen(kfd, "wb");
      if (!files[i])
      {
        fprintf(stderr, "Error fdopen %s: %s\n", names[i], strerror(errno));
        close(kfd);
        /* names[i] itself was just created, so it is removed; the ones
         * after it never were. */
        for (int j = i + 1; j < KEYPAIR_FILES; j++)
          names[j][0] = '\0';
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    /* Progress line, printed before the long streaming phase. The green
     * OK below only appears after every byte has been written and
     * flushed, so its absence tells the user a mid-generation
     * interruption left the keys unusable. On a terminal a spinner
     * (ticked once per streamed chunk) shows the work is progressing;
     * the trailing space is the placeholder its backspace overwrites. */
    int tty_out = otp_stdout_is_tty();
    printf("Generating key pair of %s MB... (wait for the %sOK%s message, if you don't see it, it failed) ",
           size_str, tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
    if (tty_out)
    {
      keypair_spinner_frame = 0;
      fputs(" ", stdout);
    }
    fflush(stdout);

    unsigned char *buf = malloc(KEYPAIR_CHUNK);
    if (!buf)
    {
      fputs("\n", stdout); /* finish the progress line before the error */
      keypair_spinner_frame = -1;
      fprintf(stderr, "Memory allocation failed\n");
      keypair_cleanup(files, names, dirs);
      return 1;
    }

    /* Pad 1 -> A's encryption key and B's decryption key.
     * Pad 2 -> A's decryption key and B's encryption key. */
    if (keypair_stream_pad(buf, size, files[0], files[3], "first") != 0 ||
        keypair_stream_pad(buf, size, files[1], files[2], "second") != 0)
    {
      fputs("\n", stdout);
      keypair_spinner_frame = -1;
      free(buf);
      keypair_cleanup(files, names, dirs);
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
        fputs("\n", stdout);
        keypair_spinner_frame = -1;
        fprintf(stderr, "Error writing %s: %s\n", names[i], strerror(errno));
        files[i] = NULL;
        keypair_cleanup(files, names, dirs);
        return 1;
      }
      files[i] = NULL;
    }

    /* Success report: the green OK the progress line promised, on its
     * own line after a blank one, then each party's directory in yellow
     * with its two keys in green. On a terminal the spinner is wiped
     * first so no stray frame remains at the end of the progress line. */
    keypair_spinner_frame = -1;
    if (tty_out)
      fputs("\b \b", stdout);
    printf("\n\n%sOK%s\n\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");

    for (int d = 0; d < KEYPAIR_DIRS; d++)
    {
      printf("%s%s_keys/%s\n", tty_out ? OTP_YELLOW : "", parts[d], tty_out ? OTP_RESET : "");
      for (int f = 0; f < 2; f++)
      {
        const char *full = names[d * 2 + f];
        const char *base = strrchr(full, '/');
        base = base ? base + 1 : full;
        printf("   %s%s%s (%zu bytes)\n",
               tty_out ? OTP_GREEN : "", base, tty_out ? OTP_RESET : "", size);
      }
      putchar('\n');
    }
    printf("Store/Share the keys safely!\n");
    return 0;
  }


  /* **************************************************************************
   *  Anything else is not a recognized command                               *
   * *********************************************************************** */

  fprintf(stderr, "Error: Unknown command. Use -h for help.\n");
  return 1;
}
