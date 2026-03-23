/*
 * AkesoAV – Self-Protection Module (P10-T2)
 *
 * Three layers per §5.11:
 *   1. DACL hardening – deny PROCESS_TERMINATE from non-admin
 *   2. WinVerifyTrust – Authenticode check on DLLs/plugins at load
 *   3. SHA-256 integrity monitoring – 60 s re-check interval
 */

#include "self_protect.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <softpub.h>
#include <wintrust.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

/* ────────────────────────────────────────────────────────────────── */
/*  1. DACL Hardening                                                */
/* ────────────────────────────────────────────────────────────────── */

/*
 * Strategy: build a new DACL for the current process that:
 *   - Allows SYSTEM and Administrators full access
 *   - Denies PROCESS_TERMINATE, PROCESS_VM_WRITE, PROCESS_VM_OPERATION
 *     to the Everyone group
 *
 * The deny ACE is placed before the allow ACEs so it takes precedence
 * for non-admin callers. Admin callers get full access via the BA ACE.
 *
 * SDDL: D:(D;;0x0021;;WD)(A;;GA;;;SY)(A;;GA;;;BA)
 *   D = deny   0x0021 = PROCESS_TERMINATE(0x1) | PROCESS_VM_WRITE(0x20)
 *   A = allow  GA = GENERIC_ALL  SY = SYSTEM  BA = Builtin Administrators
 *   WD = Everyone (World)
 */

bool akav_self_protect_harden_process(void)
{
    /* Build security descriptor from SDDL */
    const char* sddl = "D:(D;;0x0029;;WD)(A;;GA;;;SY)(A;;GA;;;BA)";
    /* 0x0029 = PROCESS_TERMINATE(0x1) | PROCESS_VM_OPERATION(0x8) | PROCESS_VM_WRITE(0x20) */

    PSECURITY_DESCRIPTOR psd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &psd, NULL)) {
        return false;
    }

    /* Extract the DACL */
    PACL dacl = NULL;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(psd, &dacl_present, &dacl, &dacl_defaulted) ||
        !dacl_present || !dacl) {
        LocalFree(psd);
        return false;
    }

    /* Apply to current process */
    HANDLE hProcess = GetCurrentProcess();
    DWORD result = SetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, dacl, NULL);

    LocalFree(psd);
    return (result == ERROR_SUCCESS);
}

/* ────────────────────────────────────────────────────────────────── */
/*  2. Authenticode Verification (WinVerifyTrust)                    */
/* ────────────────────────────────────────────────────────────────── */

akav_verify_result_t akav_self_protect_verify_authenticode(const char* file_path)
{
    if (!file_path || !file_path[0])
        return AKAV_VERIFY_ERROR;

    /* Convert to wide string */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, file_path, -1, NULL, 0);
    if (wlen <= 0)
        return AKAV_VERIFY_ERROR;

    wchar_t* wpath = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    if (!wpath)
        return AKAV_VERIFY_ERROR;
    MultiByteToWideChar(CP_UTF8, 0, file_path, -1, wpath, wlen);

    /* Set up WinVerifyTrust structures */
    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath;

    WINTRUST_DATA trust_data;
    memset(&trust_data, 0, sizeof(trust_data));
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG;

    GUID action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(
        (HWND)INVALID_HANDLE_VALUE,
        &action_id,
        &trust_data);

    /* Clean up state */
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action_id, &trust_data);

    free(wpath);

    switch (status) {
    case ERROR_SUCCESS:
        return AKAV_VERIFY_OK;
    case TRUST_E_NOSIGNATURE: {
        /* Check if the file is unsigned vs other error */
        DWORD last_err = GetLastError();
        if (last_err == TRUST_E_NOSIGNATURE ||
            last_err == TRUST_E_SUBJECT_FORM_UNKNOWN ||
            last_err == TRUST_E_PROVIDER_UNKNOWN)
            return AKAV_VERIFY_NO_SIGNATURE;
        return AKAV_VERIFY_ERROR;
    }
    case TRUST_E_EXPLICIT_DISTRUST:
    case TRUST_E_SUBJECT_NOT_TRUSTED:
    case CRYPT_E_SECURITY_SETTINGS:
        return AKAV_VERIFY_UNTRUSTED;
    case TRUST_E_BAD_DIGEST:
    case TRUST_E_COUNTER_SIGNER:
    case TRUST_E_TIME_STAMP:
        return AKAV_VERIFY_INVALID;
    default:
        return AKAV_VERIFY_INVALID;
    }
}

bool akav_self_protect_verify_dll(const char* dll_path, bool require_signed)
{
    if (!dll_path)
        return false;

    akav_verify_result_t result = akav_self_protect_verify_authenticode(dll_path);

    switch (result) {
    case AKAV_VERIFY_OK:
        return true;

    case AKAV_VERIFY_NO_SIGNATURE:
        if (require_signed) {
            fprintf(stderr, "[SELF-PROTECT] BLOCKED: unsigned DLL: %s\n", dll_path);
            return false;
        }
        /* Dev mode: allow unsigned with warning */
        fprintf(stderr, "[SELF-PROTECT] WARNING: unsigned DLL (dev mode): %s\n", dll_path);
        return true;

    case AKAV_VERIFY_INVALID:
        fprintf(stderr, "[SELF-PROTECT] BLOCKED: invalid signature: %s\n", dll_path);
        return false;

    case AKAV_VERIFY_UNTRUSTED:
        fprintf(stderr, "[SELF-PROTECT] BLOCKED: untrusted signer: %s\n", dll_path);
        return false;

    case AKAV_VERIFY_ERROR:
    default:
        fprintf(stderr, "[SELF-PROTECT] BLOCKED: verification error: %s\n", dll_path);
        return false;
    }
}

/* ────────────────────────────────────────────────────────────────── */
/*  3. SHA-256 File Integrity Monitoring                             */
/* ────────────────────────────────────────────────────────────────── */

static bool compute_sha256(const char* path, uint8_t out_hash[32])
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                     NULL, 0) != 0)
        goto done;

    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0)
        goto done;

    {
        uint8_t buf[8192];
        DWORD bytes_read;
        while (ReadFile(hFile, buf, sizeof(buf), &bytes_read, NULL) && bytes_read > 0) {
            if (BCryptHashData(hash, buf, bytes_read, 0) != 0)
                goto done;
        }
    }

    if (BCryptFinishHash(hash, out_hash, 32, 0) != 0)
        goto done;

    ok = true;

done:
    if (hash) BCryptDestroyHash(hash);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(hFile);
    return ok;
}

void akav_integrity_monitor_init(akav_integrity_monitor_t* mon,
                                  uint32_t check_interval_sec)
{
    if (!mon) return;
    memset(mon, 0, sizeof(*mon));
    mon->check_interval_sec = check_interval_sec ? check_interval_sec : 60;
    mon->initialized = true;
}

bool akav_integrity_monitor_add(akav_integrity_monitor_t* mon,
                                 const char* file_path)
{
    if (!mon || !mon->initialized || !file_path)
        return false;
    if (mon->file_count >= AKAV_SELF_PROTECT_MAX_FILES)
        return false;

    akav_monitored_file_t* entry = &mon->files[mon->file_count];

    /* Store path */
    snprintf(entry->path, sizeof(entry->path), "%s", file_path);

    /* Compute baseline hash */
    if (!compute_sha256(file_path, entry->baseline_hash))
        return false;

    entry->valid = true;
    mon->file_count++;
    return true;
}

int akav_integrity_monitor_add_dir(akav_integrity_monitor_t* mon,
                                    const char* dir_path)
{
    if (!mon || !dir_path)
        return 0;

    int added = 0;

    /* Search for *.dll and *.exe */
    const char* patterns[] = {"\\*.dll", "\\*.exe"};
    for (int p = 0; p < 2; p++) {
        char search_path[520];
        snprintf(search_path, sizeof(search_path), "%s%s", dir_path, patterns[p]);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search_path, &fd);
        if (hFind == INVALID_HANDLE_VALUE)
            continue;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            char full_path[520];
            snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, fd.cFileName);

            if (akav_integrity_monitor_add(mon, full_path))
                added++;
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }

    return added;
}

akav_integrity_result_t akav_integrity_monitor_check(
    const akav_integrity_monitor_t* mon)
{
    akav_integrity_result_t result;
    memset(&result, 0, sizeof(result));

    if (!mon || !mon->initialized)
        return result;

    int mod_idx = 0;

    for (int i = 0; i < mon->file_count; i++) {
        const akav_monitored_file_t* entry = &mon->files[i];
        if (!entry->valid)
            continue;

        result.files_checked++;

        /* Check if file still exists */
        DWORD attrs = GetFileAttributesA(entry->path);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            result.files_missing++;
            if (mod_idx < 4) {
                snprintf(result.modified_paths[mod_idx],
                         sizeof(result.modified_paths[mod_idx]),
                         "%s", entry->path);
                mod_idx++;
            }
            continue;
        }

        /* Compute current hash */
        uint8_t current_hash[32];
        if (!compute_sha256(entry->path, current_hash)) {
            result.files_error++;
            continue;
        }

        /* Compare with baseline */
        if (memcmp(current_hash, entry->baseline_hash, 32) == 0) {
            result.files_ok++;
        } else {
            result.files_modified++;
            if (mod_idx < 4) {
                snprintf(result.modified_paths[mod_idx],
                         sizeof(result.modified_paths[mod_idx]),
                         "%s", entry->path);
                mod_idx++;
            }
        }
    }

    return result;
}

void akav_integrity_monitor_destroy(akav_integrity_monitor_t* mon)
{
    if (!mon) return;
    SecureZeroMemory(mon, sizeof(*mon));
}
