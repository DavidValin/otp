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
/* Define flock as a no-op on Windows */
static inline int flock(int fd, int lock) { return 0; }
/* Map fstat to _fstat */
/* Map struct stat to _stat */
#ifndef _MSC_VER
struct stat;
#endif
/* Map localtime to localtime_s for thread safety */
#define close _close
#define open _open
#define fstat _fstat
#define getpid _getpid
#define LOCK_EX 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

int main(int argc, char *argv[])
{
  optind = 1;
  srand((unsigned)time(NULL) ^ getpid());

  /* **************************************************************************
   *  Handles -h (--help) command                                             *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
  {
    puts("\nThis program takes stdin, xor's it with a key file, outputs the result to stdout and creates a new file containing the part of the key file that was not used, ending with \".next\".\n\nUses:\n  Encrypt (using key file):\n    echo \"plain\" | otp KEY_FILE.txt > cipher.txt\n  \n  Encrypt (using keychain):\n    echo \"plain\" | otp -c <contact_name> --encrypt > cipher.txt\n  \n  Decrypt (using key file):\n    cat cipher.txt | otp KEY_FILE.txt > plain.txt\n  \n  Decrypt (using keychain):\n    cat cipher.txt | otp -c <contact_name> --decrypt > plain.txt\n  \n  Generate key pair:\n    cat /dev/urandom | otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>\n\nKeychain Commands:\n  --add-contact <name> [<enc_key_file> <dec_key_file>] (or -ac)\n\tAdd a contact to the keychain (optionally with key files)\n  --remove-contact <name> (or -rc)\tRemove a contact from the keychain\n  --has-contact <name> (or -hc)\tCheck if a contact exists\n  --list-contacts (or -lc)\t\tList all contacts\n  --show-contact <name> (or -sc)\tShow contact details\n  --contact <name> --encrypt (or -c)\tEncrypt using contact's encryption key\n  --contact <name> --decrypt (or -c)\tDecrypt using contact's decryption key\n\n");
    return 0;
  }

  /* **************************************************************************
   *  Handles keychain commands                                               *
   * *********************************************************************** */

  // Load keychain for all keychain operations
  const char *keychain_file = "keychain.txt";

  if (argc >= 3 && (strcmp(argv[1], "-ac") == 0 || strcmp(argv[1], "--add-contact") == 0))
  {
    load_keychain(keychain_file);
    int result;

    // Check if key files are provided
    if (argc >= 5)
    {
      // Add contact with keys: otp -ac <name> <enc_key_file> <dec_key_file>
      result = add_contact_with_keys(argv[2], argv[3], argv[4]);
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
    return result;
  }

  if (argc >= 3 && (strcmp(argv[1], "-rc") == 0 || strcmp(argv[1], "--remove-contact") == 0))
  {
    load_keychain(keychain_file);
    int result = remove_contact(argv[2]);
    cleanup_keychain();
    if (result == 0)
    {
      printf("Contact '%s' removed successfully\n", argv[2]);
    }
    return result;
  }

  if (argc >= 3 && (strcmp(argv[1], "-hc") == 0 || strcmp(argv[1], "--has-contact") == 0))
  {
    load_keychain(keychain_file);
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
    load_keychain(keychain_file);
    list_contacts();
    cleanup_keychain();
    return 0;
  }

  if (argc >= 3 && (strcmp(argv[1], "-sc") == 0 || strcmp(argv[1], "--show-contact") == 0))
  {
    load_keychain(keychain_file);
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

    load_keychain(keychain_file);

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
    return result;
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
    size_t size = (size_t)(size_mb * 1024 * 1024 + 0.5); // round
    if (size == 0)
    {
      fprintf(stderr, "Size too small: %s MB results in 0 bytes\n", size_str);
      return 1;
    }
    unsigned char *buf1 = malloc(size);
    if (!buf1)
    {
      fprintf(stderr, "Memory allocation failed\n");
      return 1;
    }
    if (fread(buf1, 1, size, stdin) != (size_t)size)
    {
      fprintf(stderr, "Error reading first key chunk from stdin\n");
      free(buf1);
      return 1;
    }
    unsigned char *buf2 = malloc(size);
    if (!buf2)
    {
      fprintf(stderr, "Memory allocation failed\n");
      free(buf1);
      return 1;
    }
    if (fread(buf2, 1, size, stdin) != (size_t)size)
    {
      fprintf(stderr, "Error reading second key chunk from stdin\n");
      free(buf1);
      free(buf2);
      return 1;
    }
    char fname[256];
    // encryption_part_a
    snprintf(fname, sizeof fname, "encryption_%s.txt", part_a);
    int fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
    if (fd < 0)
    {
      fprintf(stderr, "Error creating %s: %s\n", fname, strerror(errno));
      free(buf1);
      free(buf2);
      return 1;
    }
    FILE *f = fdopen(fd, "wb");
    if (!f)
    {
      fprintf(stderr, "Error fdopen %s\n", fname);
      close(fd);
      free(buf1);
      free(buf2);
      return 1;
    }
    if (fwrite(buf1, 1, size, f) != size)
    {
      fprintf(stderr, "Error writing %s\n", fname);
      fclose(f);
      free(buf1);
      free(buf2);
      return 1;
    }
    fclose(f);
    // decryption_part_a
    snprintf(fname, sizeof fname, "decryption_%s.txt", part_a);
    fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
    if (fd < 0)
    {
      fprintf(stderr, "Error creating %s: %s\n", fname, strerror(errno));
      free(buf1);
      free(buf2);
      return 1;
    }
    f = fdopen(fd, "wb");
    if (!f)
    {
      fprintf(stderr, "Error fdopen %s\n", fname);
      close(fd);
      free(buf1);
      free(buf2);
      return 1;
    }
    if (fwrite(buf2, 1, size, f) != size)
    {
      fprintf(stderr, "Error writing %s\n", fname);
      fclose(f);
      free(buf1);
      free(buf2);
      return 1;
    }
    fclose(f);
    // encryption_part_b
    snprintf(fname, sizeof fname, "encryption_%s.txt", part_b);
    fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
    if (fd < 0)
    {
      fprintf(stderr, "Error creating %s: %s\n", fname, strerror(errno));
      free(buf1);
      free(buf2);
      return 1;
    }
    f = fdopen(fd, "wb");
    if (!f)
    {
      fprintf(stderr, "Error fdopen %s\n", fname);
      close(fd);
      free(buf1);
      free(buf2);
      return 1;
    }
    if (fwrite(buf2, 1, size, f) != size)
    {
      fprintf(stderr, "Error writing %s\n", fname);
      fclose(f);
      free(buf1);
      free(buf2);
      return 1;
    }
    fclose(f);
    // decryption_part_b
    snprintf(fname, sizeof fname, "decryption_%s.txt", part_b);
    fd = open(fname, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
    if (fd < 0)
    {
      fprintf(stderr, "Error creating %s: %s\n", fname, strerror(errno));
      free(buf1);
      free(buf2);
      return 1;
    }
    f = fdopen(fd, "wb");
    if (!f)
    {
      fprintf(stderr, "Error fdopen %s\n", fname);
      close(fd);
      free(buf1);
      free(buf2);
      return 1;
    }
    if (fwrite(buf1, 1, size, f) != size)
    {
      fprintf(stderr, "Error writing %s\n", fname);
      fclose(f);
      free(buf1);
      free(buf2);
      return 1;
    }
    fclose(f);
    free(buf1);
    free(buf2);
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

  /* Build output name safely with high‑resolution timestamp and random suffix */
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
    fprintf(stderr, "Error creating output file %s: %s\\n", outfileunused, strerror(errno));
    return 1;
  }
  FILE *unused = fdopen(out_fd, "wb");
  /* Open and lock key file */
  int key_fd = open(argv[optind], O_RDONLY | O_BINARY);
  if (key_fd < 0)
  {
    fprintf(stderr, "Error opening key file %s: %s\\n", argv[optind], strerror(errno));
    close(out_fd);
    return 1;
  }
  if (flock(key_fd, LOCK_EX) < 0)
  {
    fprintf(stderr, "Error locking key file %s: %s\\n", argv[optind], strerror(errno));
    close(key_fd);
    close(out_fd);
    return 1;
  }
  FILE *infile = fdopen(key_fd, "rb");
  /* Determine key file size */
  struct stat ks;
  if (fstat(key_fd, &ks) < 0)
  {
    fprintf(stderr, "Error statting key file %s: %s\\n", argv[optind], strerror(errno));
    fclose(infile);
    fclose(unused);
    return 1;
  }
  if (!S_ISREG(ks.st_mode))
  {
    fprintf(stderr, "%s is not a regular file\\n", argv[optind]);
    fclose(infile);
    fclose(unused);
    return 1;
  }
  size_t key_size = ks.st_size;
  if (key_size == 0)
  {
    fprintf(stderr, "Key file %s is empty\\n", argv[optind]);
    fclose(infile);
    fclose(unused);
    return 1;
  }
  /* Read key into memory */
  unsigned char *keybuf = malloc(key_size);
  if (!keybuf)
  {
    fprintf(stderr, "Memory allocation failed\\n");
    fclose(infile);
    fclose(unused);
    return 1;
  }
  if (fread(keybuf, 1, key_size, infile) != key_size)
  {
    fprintf(stderr, "Error reading key file %s\\n", argv[optind]);
    free(keybuf);
    fclose(infile);
    fclose(unused);
    return 1;
  }
  /* Reset infile to start for potential further use */
  fseek(infile, 0, SEEK_SET);
  /* Handle empty stdin early */
  int first = fgetc(stdin);
  if (first == EOF)
  {
    fprintf(stderr, "No input provided; producing empty output.\\n");
    /* Write empty .next file and exit */
    fclose(infile);
    free(keybuf);
    fclose(unused);
    return 0;
  }
  /* Put the byte back for normal processing */
  ungetc(first, stdin);
  /* Ignore SIGPIPE to handle closed pipes gracefully */
  signal(SIGPIPE, SIG_IGN);
  unsigned char outbyte;
  size_t used = 0;
  while (fread(&outbyte, 1, 1, stdin) == 1)
  {
    if (used >= key_size)
    {
      fprintf(stderr, "Error: key file %s shorter than input.\\n", argv[optind]);
      free(keybuf);
      fclose(infile);
      fclose(unused);
      return 1;
    }
    /* Encrypt current byte using key */
    outbyte ^= keybuf[used];
    if (fwrite(&outbyte, 1, 1, stdout) != 1)
    {
      fprintf(stderr, "Error writing to stdout: %s\\n", strerror(errno));
      free(keybuf);
      fclose(infile);
      fclose(unused);
      return 1;
    }
    used++;
  }
  /* Write remaining key bytes to the .next key file */
  if (used < key_size)
  {
    if (fwrite(keybuf + used, 1, key_size - used, unused) != key_size - used)
    {
      fprintf(stderr, "Error writing remainder to %s: %s\\n", outfileunused, strerror(errno));
      free(keybuf);
      fclose(infile);
      fclose(unused);
      return 1;
    }
  }
  fflush(unused);
  free(keybuf);
  fclose(infile);
  fclose(unused);
  return 0;
}
