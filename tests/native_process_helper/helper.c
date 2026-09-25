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
int32_t audit_acceptance_helper(int32_t child) {
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
