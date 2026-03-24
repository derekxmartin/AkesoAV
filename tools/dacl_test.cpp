/**
 * dacl_test.exe — Test DACL protection on a target process.
 *
 * Usage:
 *   dacl_test.exe <pid>
 *
 * Attempts OpenProcess with PROCESS_TERMINATE and PROCESS_VM_WRITE.
 * Outputs results as key=value lines for PowerShell parsing.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: dacl_test.exe <pid>\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    /* Test 1: PROCESS_TERMINATE (0x0001) */
    SetLastError(0);
    HANDLE h1 = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    DWORD err1 = GetLastError();
    if (h1) {
        printf("terminate_access=allowed\n");
        printf("terminate_error=0\n");
        CloseHandle(h1);
    } else {
        printf("terminate_access=denied\n");
        printf("terminate_error=%lu\n", err1);
    }

    /* Test 2: PROCESS_VM_WRITE (0x0020) */
    SetLastError(0);
    HANDLE h2 = OpenProcess(PROCESS_VM_WRITE, FALSE, pid);
    DWORD err2 = GetLastError();
    if (h2) {
        printf("vmwrite_access=allowed\n");
        printf("vmwrite_error=0\n");
        CloseHandle(h2);
    } else {
        printf("vmwrite_access=denied\n");
        printf("vmwrite_error=%lu\n", err2);
    }

    return 0;
}
