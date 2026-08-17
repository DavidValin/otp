/*****************************************************************************\
 *                                                                           *
 *   compat.h - Cross-platform compatibility shims                           *
 *                                                                           *
 *   Provides opendir/readdir/closedir and flock()/LOCK_EX/LOCK_UN on        *
 *   Windows, backed by the Win32 FindFirstFile/FindNextFile/FindClose and   *
 *   LockFileEx/UnlockFileEx APIs, under the exact same names and semantics  *
 *   this codebase already relies on for POSIX. Every caller - the           *
 *   directory scans in commit.c (recovery-artifact lookup) and keychain.c   *
 *   (loading per-contact .meta files), and the flock() calls in             *
 *   commit.c's per-contact locking -                                        *
 *   uses these names completely unconditionally, with no #ifdef _WIN32 at   *
 *   any call site. On POSIX this header changes nothing: it just includes   *
 *   the real <dirent.h> and <sys/file.h>.                                   *
 *                                                                           *
 *   It also provides three otp_-prefixed helpers whose POSIX form needs no  *
 *   adjustment but whose Windows form genuinely differs:                    *
 *                                                                           *
 *     otp_rename_replace() - atomic rename over an existing destination.    *
 *       This is the most important one: POSIX rename() silently replaces    *
 *       an existing target, but the Windows CRT rename() *fails* with       *
 *       EEXIST instead. Every commit_publish() in commit.c lands on a path  *
 *       that already exists (a contact's .meta file, a contact's key        *
 *       file), so plain rename() would make every publish after the very    *
 *       first one fail on Windows - i.e. all keychain encrypt/decrypt would *
 *       fail there. MoveFileExA(MOVEFILE_REPLACE_EXISTING) is the Win32     *
 *       call carrying POSIX rename()'s replace-atomically semantics.        *
 *     otp_file_size() / otp_fseek() - 64-bit file sizes and offsets. The    *
 *       Windows CRT's struct stat and fseek() are 32-bit even in 64-bit     *
 *       builds, which would silently break the >2GB keys this tool exists   *
 *       to stream.                                                          *
 *                                                                           *
 *   flock(fd, LOCK_EX) blocks until the lock is acquired (LockFileEx is     *
 *   called without LOCKFILE_FAIL_IMMEDIATELY, matching that default), and   *
 *   - like the POSIX flock() this mirrors - Windows releases every lock a   *
 *   process holds as soon as its last handle to the file closes, including  *
 *   on a crash or kill, so no Windows-specific stale-lock handling is       *
 *   needed anywhere that already assumes POSIX flock()'s crash behavior.    *
 *                                                                           *
 *   Verification note: the full codebase (all Windows branches included)    *
 *   cross-compiles warning-free with real MinGW-w64 toolchains against the  *
 *   real Win32 and CRT headers - both x86_64-w64-mingw32-gcc and            *
 *   i686-w64-mingw32-gcc, -Wall -Wextra ("make mingw" runs the 64-bit       *
 *   one). That catches type, signature and missing-declaration mistakes,    *
 *   but the resulting otp.exe has not been run on actual Windows: treat     *
 *   the Windows side as compile-verified, not field-tested.                 *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef OTP_COMPAT_H
#define OTP_COMPAT_H

#ifdef _WIN32

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ---- dirent-compatible directory scanning -------------------------------
 * Minimal opendir/readdir/closedir shim exposing just d_name, which is
 * all commit.c and keychain.c ever read from an entry. Semantics match
 * POSIX closely enough for suffix-matching directory scans: opendir()
 * returns NULL if the directory doesn't exist, readdir() returns NULL
 * once entries are exhausted, and "." / ".." are returned like any other
 * entry (exactly as POSIX readdir() does) - the callers already filter
 * by filename suffix, so those are naturally skipped without any extra
 * handling here, on either platform.
 */
struct dirent
{
  char d_name[MAX_PATH];
};

typedef struct
{
  HANDLE handle;
  WIN32_FIND_DATAA find_data;
  int first;
  struct dirent entry;
} DIR;

static inline DIR *opendir(const char *path)
{
  /* Refuse rather than truncate. The callers pass buffers larger than
   * MAX_PATH, and a silently shortened pattern would not fail - it would
   * enumerate some *other*, shorter directory, which for the recovery
   * scan means reconciling against the wrong set of pending artifacts. */
  char pattern[MAX_PATH];
  int n = snprintf(pattern, sizeof(pattern), "%s\\*", path);
  if (n < 0 || (size_t)n >= sizeof(pattern))
    return NULL;

  DIR *d = (DIR *)malloc(sizeof(DIR));
  if (!d)
    return NULL;

  d->handle = FindFirstFileA(pattern, &d->find_data);
  if (d->handle == INVALID_HANDLE_VALUE)
  {
    free(d);
    return NULL;
  }
  d->first = 1;
  return d;
}

static inline struct dirent *readdir(DIR *d)
{
  if (!d)
    return NULL;

  if (!d->first)
  {
    if (!FindNextFileA(d->handle, &d->find_data))
      return NULL;
  }
  d->first = 0;

  snprintf(d->entry.d_name, sizeof(d->entry.d_name), "%s", d->find_data.cFileName);
  d->entry.d_name[sizeof(d->entry.d_name) - 1] = '\0';
  return &d->entry;
}

static inline int closedir(DIR *d)
{
  if (!d)
    return -1;
  FindClose(d->handle);
  free(d);
  return 0;
}

/* ---- flock-compatible advisory file locking -----------------------------
 * Minimal flock() shim over LockFileEx/UnlockFileEx, whole-file, matching
 * the two operations this codebase actually uses:
 *   flock(fd, LOCK_EX) - block until an exclusive lock is acquired
 *   flock(fd, LOCK_UN) - release it
 * LockFileEx blocks by default (no LOCKFILE_FAIL_IMMEDIATELY), matching
 * flock(fd, LOCK_EX)'s blocking behavior. Like POSIX flock(), Windows
 * releases all locks a process holds when its last handle to the file
 * closes - including on a crash or kill - so this composes with the rest
 * of the crash-safety design the same way the POSIX flock() does: no
 * separate stale-lock cleanup is needed on either platform.
 */
#define LOCK_EX 2
#define LOCK_UN 8

static inline int flock(int fd, int operation)
{
  HANDLE h = (HANDLE)_get_osfhandle(fd);
  if (h == INVALID_HANDLE_VALUE)
    return -1;

  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));

  if (operation == LOCK_UN)
    return UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov) ? 0 : -1;

  return LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ov) ? 0 : -1;
}

/* ---- atomic replace-rename, 64-bit sizes and offsets --------------------
 * See the header comment: these are the calls whose Windows form is not
 * merely a different spelling but a different behavior.
 */
static inline int otp_rename_replace(const char *from, const char *to)
{
  /* MOVEFILE_REPLACE_EXISTING gives the CRT rename() the one property it
   * lacks on Windows and that the whole commit protocol depends on:
   * replacing an already-existing destination in a single step, with no
   * moment where the destination is missing. */
  return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
}

static inline int otp_file_size(const char *path, unsigned long long *out)
{
  struct _stat64 st;
  if (_stat64(path, &st) != 0)
    return -1;
  *out = (unsigned long long)st.st_size;
  return 0;
}

static inline int otp_fseek(FILE *f, unsigned long long offset)
{
  return _fseeki64(f, (__int64)offset, SEEK_SET);
}

/* Open the controlling terminal for reading an interactive answer. This
 * exists because stdin cannot serve that role here: stdin carries the
 * message payload itself, so a confirmation prompt that read stdin would
 * consume ciphertext bytes as its "answer". Returns NULL when the process
 * has no terminal (a pipe-only script, cron), which callers must treat as
 * "cannot ask" - never as "assume yes". CONIN$ is the Win32 name for the
 * console input of the attached console, the moral equivalent of
 * /dev/tty; like /dev/tty it fails to open when there is no console. */
static inline FILE *otp_open_tty(void)
{
  return fopen("CONIN$", "r");
}

/* Flush a file descriptor's data to stable storage. _commit() is the CRT
 * call that hands the OS write-through request for the file's buffers. */
static inline int otp_fsync(int fd)
{
  return _commit(fd);
}

#else /* POSIX: real, unmodified system headers - no behavior change here */

#include <dirent.h>
#include <sys/file.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/* POSIX rename() already replaces an existing destination atomically, and
 * off_t is 64-bit here because both translation units define
 * _FILE_OFFSET_BITS=64 before any include (and the Makefile passes it
 * too), so these are straight pass-throughs. */
static inline int otp_rename_replace(const char *from, const char *to)
{
  return rename(from, to);
}

static inline int otp_file_size(const char *path, unsigned long long *out)
{
  struct stat st;
  if (stat(path, &st) != 0)
    return -1;
  *out = (unsigned long long)st.st_size;
  return 0;
}

static inline int otp_fseek(FILE *f, unsigned long long offset)
{
  return fseeko(f, (off_t)offset, SEEK_SET);
}

/* Flush a file descriptor's data to stable storage. On macOS fsync()
 * only pushes data to the drive - it does not force the drive to commit
 * its own cache to physical media, so a power loss right after a
 * "successful" fsync can still lose the write. F_FULLFSYNC is Apple's
 * documented way to ask for the full flush; it can fail on filesystems
 * that don't support it (SMB mounts, some externals), where plain
 * fsync() is the best available and matches other-POSIX behavior. */
static inline int otp_fsync(int fd)
{
#ifdef __APPLE__
  if (fcntl(fd, F_FULLFSYNC) != -1)
    return 0;
  return fsync(fd);
#else
  return fsync(fd);
#endif
}

/* See the Windows branch: the answer to an interactive confirmation must
 * come from the terminal, never from stdin, which carries the message
 * payload. NULL means "no terminal available", which callers must treat
 * as "cannot ask", never as "assume yes". */
static inline FILE *otp_open_tty(void)
{
  return fopen("/dev/tty", "r");
}

#endif /* _WIN32 */

#include <stdint.h>

/* Narrow a 64-bit file size into a size_t, refusing - rather than
 * silently truncating - when it does not fit. Only 32-bit builds can
 * take the failure path (SIZE_MAX there is 4GB-1); on 64-bit builds the
 * check never fires. The limit is held in a variable rather than
 * compared as a constant so 64-bit compiles don't flag the comparison
 * as always-false (-Wtype-limits). */
static inline int otp_size_to_size_t(unsigned long long v, size_t *out)
{
  unsigned long long limit = (unsigned long long)SIZE_MAX;
  if (v > limit)
    return -1;
  *out = (size_t)v;
  return 0;
}

#endif /* OTP_COMPAT_H */
