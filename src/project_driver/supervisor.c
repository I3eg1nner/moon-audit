// Process-tree supervision only. argv, pipes and waiting use the official runtime.
#include <moonbit.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
static HANDLE audit_job = NULL;
int32_t audit_isolate(void) {
  audit_job = CreateJobObjectW(NULL, NULL);
  if (!audit_job) return 0;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {0};
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(audit_job, JobObjectExtendedLimitInformation, &info, sizeof(info)) ||
      !AssignProcessToJobObject(audit_job, GetCurrentProcess())) {
    CloseHandle(audit_job); audit_job = NULL; return 0;
  }
  return 1;
}
void audit_stop_tree(int32_t pid, int32_t direct) {
  if (direct) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, (DWORD)pid);
    if (h) { TerminateProcess(h, 125); WaitForSingleObject(h, 5000); CloseHandle(h); }
  }
}
moonbit_bytes_t audit_executable(void) {
  WCHAR path[32768];
  DWORD n = GetModuleFileNameW(NULL, path, 32768);
  if (!n || n == 32768) return moonbit_make_bytes(0, 0);
  int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, n, NULL, 0, NULL, NULL);
  moonbit_bytes_t result = moonbit_make_bytes(size, 0);
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, n, (char*)result, size, NULL, NULL);
  return result;
}
#else
#include <unistd.h>
#include <signal.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <stdlib.h>
#endif
int32_t audit_isolate(void) {
  const char *parent_group = getenv("MOON_AUDIT_SUPERVISED_GROUP");
  if (parent_group && strtol(parent_group, NULL, 10) == (long)getpgrp()) return 1;
  return setsid() >= 0;
}
void audit_stop_tree(int32_t pid, int32_t direct) {
  if (pid <= 1) return;
  kill(-pid, SIGKILL);
  if (direct) { kill(pid, SIGKILL); kill(-pid, SIGKILL); }
}
moonbit_bytes_t audit_executable(void) {
  char path[32768];
#ifdef __APPLE__
  uint32_t capacity = sizeof(path);
  if (_NSGetExecutablePath(path, &capacity) != 0) return moonbit_make_bytes(0, 0);
  char resolved[32768];
  if (!realpath(path, resolved)) return moonbit_make_bytes(0, 0);
  size_t n = strlen(resolved);
  moonbit_bytes_t result = moonbit_make_bytes(n, 0);
  memcpy(result, resolved, n);
#else
  ssize_t n = readlink("/proc/self/exe", path, sizeof(path));
  if (n <= 0 || n == sizeof(path)) return moonbit_make_bytes(0, 0);
  moonbit_bytes_t result = moonbit_make_bytes(n, 0);
  memcpy(result, path, n);
#endif
  return result;
}
#endif

#ifdef _WIN32
int64_t audit_file_size(const unsigned char *path) {
  WCHAR wide[32768];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char*)path, -1, wide, 32768)) return -1;
  WIN32_FILE_ATTRIBUTE_DATA data;
  if (!GetFileAttributesExW(wide, GetFileExInfoStandard, &data)) return -1;
  if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return -2;
  return ((int64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
}
#else
#include <sys/stat.h>
int64_t audit_file_size(const unsigned char *path) {
  struct stat data;
  if (lstat((const char*)path, &data) != 0) return -1;
  if (!S_ISREG(data.st_mode) && !S_ISDIR(data.st_mode)) return -2;
  return data.st_size;
}
#endif

// Applied only inside the isolated semantic worker, before analysis allocations.
#ifdef _WIN32
int32_t audit_limit_memory(int32_t mebibytes) {
  HANDLE job = CreateJobObjectW(NULL, NULL);
  if (!job) return 0;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {0};
  info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  info.ProcessMemoryLimit = (SIZE_T)mebibytes * 1024 * 1024;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) ||
      !AssignProcessToJobObject(job, GetCurrentProcess())) { CloseHandle(job); return 0; }
  // Keep this handle for the worker lifetime; closing it is handled by the OS.
  return 1;
}
#else
#include <sys/resource.h>
int32_t audit_limit_memory(int32_t mebibytes) {
  struct rlimit limit;
  limit.rlim_cur = limit.rlim_max = (rlim_t)mebibytes * 1024 * 1024;
  if (setrlimit(RLIMIT_AS, &limit) != 0) return 0;
  // Nested compiler clients must stay in the outer semantic worker group.
  // Otherwise killing that worker would orphan clients with their own sessions.
  char group[32];
  snprintf(group, sizeof(group), "%ld", (long)getpgrp());
  return setenv("MOON_AUDIT_SUPERVISED_GROUP", group, 1) == 0;
}
#endif
