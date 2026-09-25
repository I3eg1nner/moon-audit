#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
static void wait_ms(int ms) { Sleep(ms); }
#else
#include <unistd.h>
static void wait_ms(int ms) { usleep(ms * 1000); }
#endif
static void sentinel(void) {
  const char *name = getenv("MOON_AUDIT_TEST_SENTINEL");
  if (name) { FILE *f = fopen(name, "wb"); if (f) { fputs("descendant survived", f); fclose(f); } }
}
#ifdef __APPLE__
#include <fcntl.h>
static void memory_marker(const char *event, uint64_t bytes) {
  const char *path = getenv("MOON_AUDIT_TEST_MEMORY_LOG");
  if (!path) _exit(91);
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) _exit(92);
  char record[256];
  int length = snprintf(record, sizeof(record),
    "{\"event\":\"%s\",\"pid\":%ld,\"parent\":%ld,\"group\":%ld,\"allocated_bytes\":%llu}\n",
    event, (long)getpid(), (long)getppid(), (long)getpgrp(), (unsigned long long)bytes);
  if (write(fd, record, (size_t)length) != length) _exit(93);
  close(fd);
}

static int memory_load(void) {
  // The real semantic worker has already installed the production watchdog.
  // All these processes remain in its group. Each allocates < 2 GiB, but
  // parent + child + grandchild exceed the group's 2 GiB sampling threshold.
  memory_marker("started", 0);
  pid_t child = fork();
  if (child < 0) return 90;
  if (child == 0) {
    memory_marker("started", 0);
    pid_t grandchild = fork();
    if (grandchild < 0) _exit(90);
    if (grandchild == 0) memory_marker("started", 0);
  }
  uint64_t state = (uint64_t)getpid() + 1;
  uint64_t allocated = 0;
  for (int block = 0; block < 50; block++) {
    size_t size = 16 * 1024 * 1024;
    volatile uint64_t *data = malloc(size);
    if (!data) { memory_marker("allocation_failed", allocated); return 94; }
    // Nonconstant bytes ensure real pages are touched, not merely reserved.
    for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
      state ^= state << 13; state ^= state >> 7; state ^= state << 17;
      data[i] = state;
    }
    allocated += size;
    wait_ms(20);
  }
  memory_marker("allocated", allocated);
  wait_ms(5000);
  memory_marker("survived", allocated);
  sentinel();
  return 95;
}
#endif

int32_t audit_acceptance_helper(int32_t child) {
#ifdef __APPLE__
  if (child == 2) return memory_load();
#endif
  const char *mode = getenv("MOON_AUDIT_TEST_MODE");
  if (child) { wait_ms(3000); sentinel(); return 0; }
  if (mode && strcmp(mode, "flood") == 0) {
    char block[8192]; memset(block, 'x', sizeof(block));
    for (int i = 0; i < 4096; i++) { fwrite(block, 1, sizeof(block), stdout); fwrite(block, 1, sizeof(block), stderr); }
    return 0;
  }
  if (mode && strcmp(mode, "change") == 0) {
    FILE *source = fopen("danger.mbt", "ab");
    if (source) { fputs("\n// changed during compilation\n", source); fclose(source); }
    puts("moonc check danger.mbt"); return 0;
  }
  if (mode && strcmp(mode, "bad-plan") == 0) { puts("unrecognized planner format"); return 0; }
#ifdef _WIN32
  WCHAR exe[32768], line[32790];
  GetModuleFileNameW(NULL, exe, 32768);
  _snwprintf(line, 32790, L"\"%ls\" --child", exe);
  STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
  PROCESS_INFORMATION proc = {0};
  if (!CreateProcessW(exe, line, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &proc)) return 90;
  CloseHandle(proc.hThread); CloseHandle(proc.hProcess);
#else
  pid_t pid = fork();
  if (pid < 0) return 90;
  if (!pid) { wait_ms(3000); sentinel(); _exit(0); }
#endif
  wait_ms(60000);
  return 0;
}
