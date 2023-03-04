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
  int nreadfile, nreadstdin;
  int i;

  infile=fopen(argv[optind], "r");
  unused_infile_file_part = fopen(outfileunused, "w");

  if (fseek(infile, 0, SEEK_SET))  {
    fputs("Error opening file\n", stderr);
    return -1;  
  }
  if (fseek(unused_infile_file_part, 0, SEEK_SET))  {
    fputs("Error opening file\n", stderr);
    return -1;  
  }

  while(1) {
    nreadstdin=fread(&stdinbuffer, 1, 1, stdin);
    if (nreadstdin==1) {
      nreadfile=fread(&filebuffer, 1, 1, infile);
      if (nreadfile==1) {
        stdinbuffer^=filebuffer;
        fwrite(&stdinbuffer, 1, min(nreadstdin, nreadfile), stdout);
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
    nreadfile=fread(&filebuffer, 1, 1, infile);
    if (nreadfile==1) {
      fwrite(&filebuffer, 1, nreadfile, unused_infile_file_part);
    } else {
      break;
    }
  }

  fclose(infile);
  fclose(unused_infile_file_part);
}
