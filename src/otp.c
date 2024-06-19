#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

int min( int a, int b) {if (a<b) return a; return b;}

int main(int argc, char *argv[]) {
  unsigned char instructions[] = "\nThis program takes stdin, xor's it with a key file, outputs the result to stdout and creates a new file containing the part of the key file that was not used, ending with \".next\".\n\nUses:\n  encrypt\techo \"plain\" | otp KEY_FILE.txt > cipher.txt\n  decrypt\tcat cipher.txt | otp KEY_FILE.txt > plain.txt\n\n";
  if (argc == 1) {
    puts(instructions);
    exit(0);
  }

  char outfileunused[1024];
  sprintf(outfileunused, argv[optind]);
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  sprintf(outfileunused+strlen(argv[optind]), ".%d-%02d-%02d_%02d:%02d:%02d.next", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  struct stat buffer;
  if (stat (outfileunused, &buffer) == 0) {
    fputs("\n  A file named %s already exists, please remove it\n\n", stderr);
    return -1;
  }

  FILE *infile;
	FILE *unused_infile_file_part;
  unsigned char filebuffer;
  unsigned char stdinbuffer;
  int nreadfile, nreadfile2, nreadstdin;
  int i;

  infile=fopen(argv[optind], "r");
  unused_infile_file_part = fopen(outfileunused, "w");

  if (infile == NULL) {
    fputs("Error opening input key file, check that it exist\n", stderr);
    return -1;
  }
  if (unused_infile_file_part == NULL)  {
    fputs("Error opening next input key file\n", stderr);
    return -1;
  }

  while(1) {
    nreadstdin=fread(&stdinbuffer, 1, sizeof(unsigned char), stdin);
    if (nreadstdin==1) {
      nreadfile=fread(&filebuffer, 1, sizeof(unsigned char), infile);
      if (nreadfile==1) {
        stdinbuffer^=filebuffer;
        fwrite(&stdinbuffer, 1, sizeof(unsigned char), stdout);
        fflush(stdout);
        continue;
      } else {
        printf("\n Error! Key file not as long as stdin input.\n");
        return -1;
      }
    } else {
      break;
    }
  }

  // produce new file excluding the part of the key that was used
  while(1) {
    nreadfile2=fread(&filebuffer, 1, sizeof(unsigned char), infile);
    if (nreadfile2==1) {
      fwrite(&filebuffer, 1, sizeof(unsigned char), unused_infile_file_part);
      fflush(unused_infile_file_part);
    } else {
      break;
    }
  }

  fclose(stdin);
  fclose(stdout);
  fclose(infile);
  fclose(unused_infile_file_part);
}
