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
#ifdef __APPLE__
  if (setsid() < 0) return 0;
  char group[32];
  snprintf(group, sizeof(group), "%ld", (long)getpgrp());
  return setenv("MOON_AUDIT_SUPERVISED_GROUP", group, 1) == 0;
#else
  return setsid() >= 0;
#endif
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
#elif defined(__APPLE__)
#include <errno.h>
#include <libproc.h>
#include <pthread.h>
#include <time.h>
#include <sys/resource.h>

// Darwin's virtual mappings are not a useful absolute working-memory budget.
// Sample the physical footprint of the entire isolated worker group instead.
// This is a cancellation threshold, not an allocation-time hard bound: CPU
// scheduling and allocations between samples can cause a temporary overshoot.
#define AUDIT_MEMORY_SAMPLE_MS 50
#define AUDIT_MEMORY_MAX_PROCESSES 4096
struct audit_memory_watch {
  pid_t group;
  uint64_t limit;
  uint64_t started_ns;
};
static struct audit_memory_watch audit_watch;

static uint64_t audit_monotonic_ns(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void audit_memory_diagnostic(const char *event, uint64_t bytes,
                                    int count, uint64_t gap_ns, int error) {
  char message[768];
  int n = snprintf(message, sizeof(message),
    "MOON_AUDIT_MEMORY {\"event\":\"%s\",\"mechanism\":\"process_group_physical_footprint_sampling\","
    "\"group\":%ld,\"limit_bytes\":%llu,\"observed_bytes\":%llu,\"processes\":%d,"
    "\"sample_interval_ms\":%d,\"sample_gap_ms\":%llu,\"elapsed_ms\":%llu,\"errno\":%d}\n",
    event, (long)audit_watch.group, (unsigned long long)audit_watch.limit,
    (unsigned long long)bytes, count, AUDIT_MEMORY_SAMPLE_MS,
    (unsigned long long)(gap_ns / 1000000ULL),
    (unsigned long long)((audit_monotonic_ns() - audit_watch.started_ns) / 1000000ULL), error);
  if (n > 0) {
    size_t size = (size_t)n < sizeof(message) ? (size_t)n : sizeof(message) - 1;
    // One bounded write avoids stdio locks held by an allocation-heavy thread.
    (void)write(STDERR_FILENO, message, size);
  }
}

static int audit_group_footprint(uint64_t *total, int *members) {
  pid_t pids[AUDIT_MEMORY_MAX_PROCESSES];
  *total = 0; *members = 0;
  int count = proc_listpgrppids(audit_watch.group, pids, sizeof(pids));
  if (count <= 0) { errno = ESRCH; return 0; }
  if (count >= AUDIT_MEMORY_MAX_PROCESSES) { errno = EOVERFLOW; return 0; }
  for (int i = 0; i < count; i++) {
    if (pids[i] <= 0) continue;
    pid_t group = getpgid(pids[i]);
    if (group < 0 && errno == ESRCH) continue;
    if (group != audit_watch.group) { if (group < 0) return 0; else continue; }
    struct rusage_info_v4 usage = {0};
    if (proc_pid_rusage(pids[i], RUSAGE_INFO_V4, (rusage_info_t *)&usage) != 0) {
      if (errno == ESRCH) continue;
      return 0;
    }
    if (UINT64_MAX - *total < usage.ri_phys_footprint) { errno = EOVERFLOW; return 0; }
    *total += usage.ri_phys_footprint;
    *members += 1;
  }
  if (*members == 0) { errno = ESRCH; return 0; }
  return 1;
}

static void *audit_memory_monitor(void *unused) {
  (void)unused;
  uint64_t previous = audit_monotonic_ns();
  for (;;) {
    struct timespec remaining = {0, AUDIT_MEMORY_SAMPLE_MS * 1000000L};
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {}
    uint64_t now = audit_monotonic_ns(), bytes = 0;
    int members = 0;
    if (!audit_group_footprint(&bytes, &members)) {
      int error = errno;
      audit_memory_diagnostic("sampling_failed", bytes, members, now - previous, error);
      kill(-audit_watch.group, SIGKILL);
      _exit(125);
    }
    if (bytes > audit_watch.limit) {
      audit_memory_diagnostic("budget_exhausted", bytes, members, now - previous, 0);
      kill(-audit_watch.group, SIGKILL);
      _exit(125);
    }
    previous = now;
  }
}

int32_t audit_limit_memory(int32_t mebibytes) {
  audit_watch.group = getpgrp();
  audit_watch.limit = mebibytes > 0 ? (uint64_t)mebibytes * 1024 * 1024 : 0;
  audit_watch.started_ns = audit_monotonic_ns();
  const char *marked_group = getenv("MOON_AUDIT_SUPERVISED_GROUP");
  if (!marked_group || strtol(marked_group, NULL, 10) != (long)audit_watch.group ||
      audit_watch.group <= 1 || getsid(0) != audit_watch.group || !audit_watch.limit) {
    audit_memory_diagnostic("invalid_isolated_group", 0, 0, 0, EINVAL);
    return 0;
  }
  uint64_t bytes = 0;
  int members = 0;
  if (!audit_group_footprint(&bytes, &members)) {
    audit_memory_diagnostic("initial_sampling_failed", bytes, members, 0, errno);
    return 0;
  }
  if (bytes > audit_watch.limit) {
    audit_memory_diagnostic("initial_budget_exhausted", bytes, members, 0, 0);
    return 0;
  }
  pthread_attr_t attributes;
  int error = pthread_attr_init(&attributes);
  if (error != 0) { audit_memory_diagnostic("thread_attributes_failed", bytes, members, 0, error); return 0; }
  error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
  pthread_t thread;
  if (error == 0) error = pthread_create(&thread, &attributes, audit_memory_monitor, NULL);
  pthread_attr_destroy(&attributes);
  if (error != 0) { audit_memory_diagnostic("monitor_start_failed", bytes, members, 0, error); return 0; }
  audit_memory_diagnostic("monitor_started", bytes, members, 0, 0);
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

// Stable protocol discriminator for the report; no platform inference in CLI.
int32_t audit_memory_policy(void) {
#ifdef _WIN32
  return 2;
#elif defined(__APPLE__)
  return 3;
#else
  return 1;
#endif
}
