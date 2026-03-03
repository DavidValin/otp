/*****************************************************************************\
 *                                                                            *
 *   otp v1.0.3                                                               *
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <getopt.h>

int main(int argc, char *argv[]) {
  optind = 1;
  srand((unsigned)time(NULL) ^ getpid());

  /* **************************************************************************
   *  Handles -h (--help) command                                             *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    puts("\nThis program takes stdin, xor's it with a key file, outputs the result to stdout and creates a new file containing the part of the key file that was not used, ending with \".next\".\n\nUses:\n  encrypt\tcecho \"plain\" | otp KEY_FILE.txt > cipher.txt\n  decrypt\tcat cipher.txt | otp KEY_FILE.txt > plain.txt\n  new-key-pair\tcat /dev/urandom | otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>\n\n");
    return 0;
  }

  /* **************************************************************************
   *  Handles -nk (--new-key-pair) command                                    *
   * *********************************************************************** */

  if (argc >= 5 && (strcmp(argv[1], "-nk") == 0 || strcmp(argv[1], "--new-key-pair") == 0)) {
    const char *size_str = argv[2];
    char *endptr = NULL;
    double size_mb = strtod(size_str, &endptr);
    if (endptr == size_str || size_mb <= 0) {
      fprintf(stderr, "Invalid size %s MB\n", size_str);
      return 1;
    }
    const char *part_a = argv[3];
    const char *part_b = argv[4];
    size_t size = (size_t)(size_mb * 1024 * 1024 + 0.5); // round
    if (size == 0) {
      fprintf(stderr, "Size too small: %s MB results in 0 bytes\n", size_str);
      return 1;
    }
    unsigned char *buf1 = malloc(size);
    if (!buf1) {fprintf(stderr,"Memory allocation failed\n");return 1;}
    if (fread(buf1, 1, size, stdin) != (size_t)size) {
      fprintf(stderr,"Error reading first key chunk from stdin\n");
      free(buf1); return 1;
    }
    unsigned char *buf2 = malloc(size);
    if (!buf2) {fprintf(stderr,"Memory allocation failed\n");free(buf1);return 1;}
    if (fread(buf2, 1, size, stdin) != (size_t)size) {
      fprintf(stderr,"Error reading second key chunk from stdin\n");
      free(buf1); free(buf2); return 1;
    }
    char fname[256];
    // encryption_part_a
    snprintf(fname, sizeof fname, "encryption_%s.txt", part_a);
    int fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {fprintf(stderr,"Error creating %s: %s\n", fname, strerror(errno)); free(buf1); free(buf2); return 1;}
    FILE *f = fdopen(fd, "wb");
    if (!f) {fprintf(stderr,"Error fdopen %s\n", fname); close(fd); free(buf1); free(buf2); return 1;}
    if (fwrite(buf1, 1, size, f) != size) {fprintf(stderr,"Error writing %s\n", fname); fclose(f); free(buf1); free(buf2); return 1;}
    fclose(f);
    // decryption_part_a
    snprintf(fname, sizeof fname, "decryption_%s.txt", part_a);
    fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {fprintf(stderr,"Error creating %s: %s\n", fname, strerror(errno)); free(buf1); free(buf2); return 1;}
    f = fdopen(fd, "wb");
    if (!f) {fprintf(stderr,"Error fdopen %s\n", fname); close(fd); free(buf1); free(buf2); return 1;}
    if (fwrite(buf2, 1, size, f) != size) {fprintf(stderr,"Error writing %s\n", fname); fclose(f); free(buf1); free(buf2); return 1;}
    fclose(f);
    // encryption_part_b
    snprintf(fname, sizeof fname, "encryption_%s.txt", part_b);
    fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {fprintf(stderr,"Error creating %s: %s\n", fname, strerror(errno)); free(buf1); free(buf2); return 1;}
    f = fdopen(fd, "wb");
    if (!f) {fprintf(stderr,"Error fdopen %s\n", fname); close(fd); free(buf1); free(buf2); return 1;}
    if (fwrite(buf2, 1, size, f) != size) {fprintf(stderr,"Error writing %s\n", fname); fclose(f); free(buf1); free(buf2); return 1;}
    fclose(f);
    // decryption_part_b
    snprintf(fname, sizeof fname, "decryption_%s.txt", part_b);
    fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {fprintf(stderr,"Error creating %s: %s\n", fname, strerror(errno)); free(buf1); free(buf2); return 1;}
    f = fdopen(fd, "wb");
    if (!f) {fprintf(stderr,"Error fdopen %s\n", fname); close(fd); free(buf1); free(buf2); return 1;}
    if (fwrite(buf1, 1, size, f) != size) {fprintf(stderr,"Error writing %s\n", fname); fclose(f); free(buf1); free(buf2); return 1;}
    fclose(f);
    free(buf1); free(buf2);
    return 0;
  }

  /* **************************************************************************
   *  Handles encryption / decryption via stdin + key file                    *
   * *********************************************************************** */

  /* Build output name safely with high‑resolution timestamp and random suffix */
  char outfileunused[256];
  time_t t = time(NULL);
  struct tm tm_struct = *localtime(&t);
  snprintf(outfileunused, sizeof outfileunused,
    "%s.%04d-%02d-%02d_%02d-%02d-%02d.next",
    argv[optind],
    tm_struct.tm_year + 1900, tm_struct.tm_mon + 1, tm_struct.tm_mday,
    tm_struct.tm_hour, tm_struct.tm_min, tm_struct.tm_sec);
  /* Ensure unique output file atomically (O_CREAT|O_EXCL) */
  int out_fd = open(outfileunused, O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (out_fd < 0) {
    fprintf(stderr, "Error creating output file %s: %s\\n", outfileunused, strerror(errno));
    return 1;
  }
  FILE *unused = fdopen(out_fd, "wb");
  /* Open and lock key file */
  int key_fd = open(argv[optind], O_RDONLY);
  if (key_fd < 0) {
    fprintf(stderr, "Error opening key file %s: %s\\n", argv[optind], strerror(errno));
    close(out_fd);
    return 1;
  }
  if (flock(key_fd, LOCK_EX) < 0) {
    fprintf(stderr, "Error locking key file %s: %s\\n", argv[optind], strerror(errno));
    close(key_fd); close(out_fd);
    return 1;
  }
  FILE *infile = fdopen(key_fd, "rb");
  /* Determine key file size */
  struct stat ks;
  if (fstat(key_fd, &ks) < 0) {
    fprintf(stderr, "Error statting key file %s: %s\\n", argv[optind], strerror(errno));
    fclose(infile); fclose(unused);
    return 1;
  }
  if (!S_ISREG(ks.st_mode)) {
    fprintf(stderr, "%s is not a regular file\\n", argv[optind]);
    fclose(infile); fclose(unused);
    return 1;
  }
  size_t key_size = ks.st_size;
  if (key_size == 0) {
    fprintf(stderr, "Key file %s is empty\\n", argv[optind]);
    fclose(infile); fclose(unused);
    return 1;
  }
  /* Read key into memory */
  unsigned char *keybuf = malloc(key_size);
  if (!keybuf) {
    fprintf(stderr, "Memory allocation failed\\n");
    fclose(infile); fclose(unused);
    return 1;
  }
  if (fread(keybuf, 1, key_size, infile) != key_size) {
    fprintf(stderr, "Error reading key file %s\\n", argv[optind]);
    free(keybuf); fclose(infile); fclose(unused);
    return 1;
  }
  /* Reset infile to start for potential further use */
  fseek(infile, 0, SEEK_SET);
  /* Handle empty stdin early */
  int first = fgetc(stdin);
  if (first == EOF) {
    fprintf(stderr, "No input provided; producing empty output.\\n");
    /* Write empty .next file and exit */
    fclose(infile); free(keybuf);
    fclose(unused);
    return 0;
  }
  /* Put the byte back for normal processing */
  ungetc(first, stdin);
  /* Ignore SIGPIPE to handle closed pipes gracefully */
  signal(SIGPIPE, SIG_IGN);
  unsigned char outbyte;
  size_t used = 0;
  while (fread(&outbyte, 1, 1, stdin) == 1) {
    if (used >= key_size) {
      fprintf(stderr, "Error: key file %s shorter than input.\\n", argv[optind]);
      free(keybuf); fclose(infile); fclose(unused);
      return 1;
    }
    /* Encrypt current byte using key */
    outbyte ^= keybuf[used];
    if (fwrite(&outbyte, 1, 1, stdout) != 1) {
      fprintf(stderr, "Error writing to stdout: %s\\n", strerror(errno));
      free(keybuf); fclose(infile); fclose(unused);
      return 1;
    }
    used++;
  }
  /* Write remaining key bytes to the .next key file */
  if (used < key_size) {
    if (fwrite(keybuf + used, 1, key_size - used, unused) != key_size - used) {
      fprintf(stderr, "Error writing remainder to %s: %s\\n", outfileunused, strerror(errno));
      free(keybuf); fclose(infile); fclose(unused);
      return 1;
    }
  }
  fflush(unused);
  free(keybuf); fclose(infile); fclose(unused);
  return 0;
}
