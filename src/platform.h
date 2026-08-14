/*****************************************************************************\
 *                                                                           *
 *   platform.h - Cross-platform compatibility shims                         *
 *                                                                           *
 *   Provides opendir/readdir/closedir and flock()/LOCK_EX/LOCK_UN on        *
 *   Windows, backed by the Win32 FindFirstFile/FindNextFile/FindClose and   *
 *   LockFileEx/UnlockFileEx APIs, under the exact same names and semantics  *
 *   this codebase already relies on for POSIX. Every caller - the           *
 *   directory scans in commit.c (recovery-artifact lookup) and keychain.c   *
 *   (loading per-contact .meta files), and the flock() calls in             *
 *   commit.c's per-contact locking and otp.c's direct key-file mode -       *
 *   uses these names completely unconditionally, with no #ifdef _WIN32 at   *
 *   any call site. On POSIX this header changes nothing: it just includes   *
 *   the real <dirent.h> and <sys/file.h>.                                   *
 *                                                                           *
 *   flock(fd, LOCK_EX) blocks until the lock is acquired (LockFileEx is     *
 *   called without LOCKFILE_FAIL_IMMEDIATELY, matching that default), and   *
 *   - like the POSIX flock() this mirrors - Windows releases every lock a   *
 *   process holds as soon as its last handle to the file closes, including  *
 *   on a crash or kill, so no Windows-specific stale-lock handling is       *
 *   needed anywhere that already assumes POSIX flock()'s crash behavior.    *
 *                                                                           *
 *   Verification note: no Windows/mingw toolchain was available while       *
 *   writing this, so it has not been built or run on actual Windows. The    *
 *   Windows branch below was compiled in isolation (gcc -D_WIN32) against   *
 *   stub headers whose declarations match the real Win32 API signatures     *
 *   (FindFirstFileA, LockFileEx, etc.), exercised the same way commit.c     *
 *   and keychain.c actually call it - which catches type/argument-order     *
 *   mistakes, but is not a substitute for a real Windows build and test     *
 *   run. Treat this implementation as reviewed, not field-tested.           *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef OTP_PLATFORM_H
#define OTP_PLATFORM_H

#ifdef _WIN32

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static DIR *opendir(const char *path)
{
  char pattern[MAX_PATH];
  snprintf(pattern, sizeof(pattern), "%s\\*", path);
  pattern[sizeof(pattern) - 1] = '\0';

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

static struct dirent *readdir(DIR *d)
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

static int closedir(DIR *d)
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

static int flock(int fd, int operation)
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

#else /* POSIX: real, unmodified system headers - no behavior change here */

#include <dirent.h>
#include <sys/file.h>

#endif /* _WIN32 */

#endif /* OTP_PLATFORM_H */
