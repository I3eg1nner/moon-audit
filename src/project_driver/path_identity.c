// Filesystem identity for existing ordinary paths. Lexical fallback stays in MoonBit.
#include <moonbit.h>
#include <string.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>

moonbit_bytes_t audit_path_identity(const unsigned char *path) {
  WCHAR wide[32768];
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)path,
                          -1, wide, 32768)) return moonbit_make_bytes(0, 0);
  DWORD attributes = GetFileAttributesW(wide);
  if (attributes == INVALID_FILE_ATTRIBUTES ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return moonbit_make_bytes(0, 0);
  HANDLE file = CreateFileW(wide, 0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) return moonbit_make_bytes(0, 0);
  DWORD length = GetFinalPathNameByHandleW(file, wide, 32768,
                                         FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  CloseHandle(file);
  if (!length || length >= 32768) return moonbit_make_bytes(0, 0);
  // The language filesystem APIs consume ordinary DOS/UNC paths, not device paths.
  if (length >= 8 && wcsncmp(wide, L"\\\\?\\UNC\\", 8) == 0) {
    memmove(wide + 2, wide + 8, (length - 8 + 1) * sizeof(WCHAR));
    wide[0] = wide[1] = L'\\';
    length -= 6;
  } else if (length >= 4 && wcsncmp(wide, L"\\\\?\\", 4) == 0) {
    memmove(wide, wide + 4, (length - 4 + 1) * sizeof(WCHAR));
    length -= 4;
  }
  if (length >= 2 && wide[1] == L':' && wide[0] >= L'a' && wide[0] <= L'z') {
    wide[0] -= L'a' - L'A';
  }
  int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, length,
                                 NULL, 0, NULL, NULL);
  if (size <= 0) return moonbit_make_bytes(0, 0);
  moonbit_bytes_t result = moonbit_make_bytes(size, 0);
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, length,
                      (char *)result, size, NULL, NULL);
  return result;
}
#else
#include <stdlib.h>
#include <sys/stat.h>
moonbit_bytes_t audit_path_identity(const unsigned char *path) {
  struct stat status;
  // Do not erase a selected symlink or special file before snapshot validation.
  if (lstat((const char *)path, &status) != 0 ||
      (!S_ISREG(status.st_mode) && !S_ISDIR(status.st_mode))) {
    return moonbit_make_bytes(0, 0);
  }
  char *resolved = realpath((const char *)path, NULL);
  if (!resolved) return moonbit_make_bytes(0, 0);
  size_t length = strlen(resolved);
  moonbit_bytes_t result = moonbit_make_bytes(length, 0);
  memcpy(result, resolved, length);
  free(resolved);
  return result;
}
#endif
