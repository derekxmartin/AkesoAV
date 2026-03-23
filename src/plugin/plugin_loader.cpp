/* plugin_loader.cpp -- Dynamic plugin loading implementation (P6-T3).
 *
 * Loads plugin DLLs via LoadLibrary, resolves the akav_plugin_get_info
 * entry point, validates API version, and manages plugin lifecycle.
 */

#include "plugin/plugin_loader.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <cstdio>

/* ── Initialization ── */

void akav_plugin_manager_init(akav_plugin_manager_t* mgr)
{
    if (!mgr) return;
    memset(mgr, 0, sizeof(*mgr));
}

/* ── Load a single plugin DLL ── */

akav_error_t akav_plugin_manager_load(akav_plugin_manager_t* mgr,
                                       const char* dll_path)
{
    if (!mgr || !dll_path)
        return AKAV_ERROR_INVALID;

    if (mgr->count >= AKAV_MAX_PLUGINS) {
        fprintf(stderr, "[plugin] Cannot load '%s': max plugin limit (%d) reached\n",
                dll_path, AKAV_MAX_PLUGINS);
        return AKAV_ERROR;
    }

    /* Load the DLL */
    HMODULE hModule = LoadLibraryA(dll_path);
    if (!hModule) {
        fprintf(stderr, "[plugin] Failed to load '%s': error %lu\n",
                dll_path, GetLastError());
        return AKAV_ERROR_IO;
    }

    /* Resolve entry point */
    auto get_info = (akav_plugin_get_info_fn)GetProcAddress(
        hModule, "akav_plugin_get_info");
    if (!get_info) {
        fprintf(stderr, "[plugin] '%s': missing akav_plugin_get_info export\n",
                dll_path);
        FreeLibrary(hModule);
        return AKAV_ERROR_INVALID;
    }

    /* Get plugin info */
    const akav_plugin_info_t* info = get_info();
    if (!info) {
        fprintf(stderr, "[plugin] '%s': akav_plugin_get_info returned NULL\n",
                dll_path);
        FreeLibrary(hModule);
        return AKAV_ERROR_INVALID;
    }

    /* Validate API version (major must match exactly) */
    if (info->api_version_major != AKAV_PLUGIN_API_VERSION_MAJOR) {
        fprintf(stderr, "[plugin] Skipping '%s' (%s): API version %u.%u, expected %u.x\n",
                dll_path,
                info->name ? info->name : "unknown",
                info->api_version_major, info->api_version_minor,
                AKAV_PLUGIN_API_VERSION_MAJOR);
        FreeLibrary(hModule);
        return AKAV_ERROR_INVALID;
    }

    /* Validate name is present */
    if (!info->name) {
        fprintf(stderr, "[plugin] '%s': plugin info has NULL name\n", dll_path);
        FreeLibrary(hModule);
        return AKAV_ERROR_INVALID;
    }

    /* Scanner plugins must have a scan function */
    if ((info->type & AKAV_PLUGIN_TYPE_SCANNER) && !info->scan) {
        fprintf(stderr, "[plugin] '%s' (%s): SCANNER type but scan callback is NULL\n",
                dll_path, info->name);
        FreeLibrary(hModule);
        return AKAV_ERROR_INVALID;
    }

    /* Call plugin init if provided */
    void* plugin_ctx = nullptr;
    if (info->init) {
        int rc = info->init(&plugin_ctx);
        if (rc != 0) {
            fprintf(stderr, "[plugin] '%s' (%s): init() failed with code %d\n",
                    dll_path, info->name, rc);
            FreeLibrary(hModule);
            return AKAV_ERROR;
        }
    }

    /* Register plugin */
    akav_loaded_plugin_t* slot = &mgr->plugins[mgr->count];
    slot->dll_handle = (void*)hModule;
    slot->info = info;
    slot->plugin_ctx = plugin_ctx;
    slot->active = 1;
    mgr->count++;

    fprintf(stderr, "[plugin] Loaded '%s' v%s (type 0x%x, API %u.%u)\n",
            info->name,
            info->version ? info->version : "?",
            info->type,
            info->api_version_major, info->api_version_minor);

    return AKAV_OK;
}

/* ── Load all DLLs from a directory ── */

int akav_plugin_manager_load_dir(akav_plugin_manager_t* mgr,
                                  const char* dir_path)
{
    if (!mgr || !dir_path)
        return 0;

    /* Build search pattern: dir_path\*.dll */
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.dll", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;  /* No DLLs found or directory doesn't exist */

    int loaded = 0;
    do {
        /* Skip directories */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        /* Build full path */
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, fd.cFileName);

        akav_error_t err = akav_plugin_manager_load(mgr, full_path);
        if (err == AKAV_OK)
            loaded++;

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return loaded;
}

/* ── Run scanner plugins ── */

void akav_plugin_manager_scan(const akav_plugin_manager_t* mgr,
                               const uint8_t* data, size_t data_len,
                               const akav_scan_options_t* opts,
                               akav_scan_result_t* result)
{
    if (!mgr || !data || !result)
        return;

    for (int i = 0; i < mgr->count; i++) {
        const akav_loaded_plugin_t* p = &mgr->plugins[i];
        if (!p->active)
            continue;
        if (!(p->info->type & AKAV_PLUGIN_TYPE_SCANNER))
            continue;
        if (!p->info->scan)
            continue;

        p->info->scan(data, data_len, opts, result, p->plugin_ctx);

        if (result->found)
            return;  /* Short-circuit on first detection */
    }
}

/* ── Shutdown and cleanup ── */

void akav_plugin_manager_destroy(akav_plugin_manager_t* mgr)
{
    if (!mgr)
        return;

    /* Shutdown in reverse order */
    for (int i = mgr->count - 1; i >= 0; i--) {
        akav_loaded_plugin_t* p = &mgr->plugins[i];
        if (!p->active)
            continue;

        /* Call plugin shutdown */
        if (p->info && p->info->shutdown)
            p->info->shutdown(p->plugin_ctx);

        /* Unload DLL */
        if (p->dll_handle)
            FreeLibrary((HMODULE)p->dll_handle);
    }

    memset(mgr, 0, sizeof(*mgr));
}
