/* plugin_loader.h -- Dynamic plugin loading for AkesoAV (P6-T3).
 *
 * Each plugin DLL exports a single C function:
 *     const akav_plugin_info_t* akav_plugin_get_info(void);
 *
 * The engine loads plugins from a directory, validates API version
 * compatibility, and invokes scanner callbacks during the scan pipeline.
 */
#ifndef AKAV_PLUGIN_LOADER_H
#define AKAV_PLUGIN_LOADER_H

#include "akesoav.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plugin API version -- bump major on breaking ABI changes. */
#define AKAV_PLUGIN_API_VERSION_MAJOR  1
#define AKAV_PLUGIN_API_VERSION_MINOR  0

/* Plugin type flags. */
#define AKAV_PLUGIN_TYPE_SCANNER  0x01   /* Scans buffer, may set result->found */
#define AKAV_PLUGIN_TYPE_PARSER   0x02   /* Extracts/transforms content         */

/* Maximum number of plugins loaded simultaneously. */
#define AKAV_MAX_PLUGINS  32

/* ── Plugin callback signatures ── */

/* Scanner callback: inspect buffer, populate result on detection.
 * Return AKAV_OK on success (detection or not). */
typedef akav_error_t (*akav_plugin_scan_fn)(
    const uint8_t* data, size_t data_len,
    const akav_scan_options_t* opts,
    akav_scan_result_t* result,
    void* plugin_ctx);

/* Lifecycle: init returns 0 on success, non-zero on failure. */
typedef int  (*akav_plugin_init_fn)(void** plugin_ctx);
typedef void (*akav_plugin_shutdown_fn)(void* plugin_ctx);

/* ── Plugin info (static lifetime, owned by DLL) ── */
typedef struct {
    uint32_t    api_version_major;
    uint32_t    api_version_minor;
    const char* name;           /* Human-readable, e.g. "PLUGINTEST Scanner" */
    const char* version;        /* Plugin version string, e.g. "1.0.0"      */
    uint32_t    type;           /* AKAV_PLUGIN_TYPE_SCANNER, _PARSER, or both */
    akav_plugin_init_fn     init;       /* Optional (may be NULL) */
    akav_plugin_shutdown_fn shutdown;   /* Optional (may be NULL) */
    akav_plugin_scan_fn     scan;       /* Required for SCANNER type */
} akav_plugin_info_t;

/* Entry point that every plugin DLL must export. */
typedef const akav_plugin_info_t* (*akav_plugin_get_info_fn)(void);

/* ── Loaded plugin runtime state ── */
typedef struct {
    void*                       dll_handle;  /* HMODULE from LoadLibrary      */
    const akav_plugin_info_t*   info;        /* Pointer into DLL static data  */
    void*                       plugin_ctx;  /* Context returned by init()    */
    int                         active;      /* 1 if successfully initialized */
} akav_loaded_plugin_t;

/* ── Plugin manager ── */
typedef struct {
    akav_loaded_plugin_t plugins[AKAV_MAX_PLUGINS];
    int                  count;
} akav_plugin_manager_t;

/* Initialize the plugin manager (zeroes state). */
void akav_plugin_manager_init(akav_plugin_manager_t* mgr);

/* Load a single plugin DLL by path. Returns AKAV_OK or error code. */
akav_error_t akav_plugin_manager_load(akav_plugin_manager_t* mgr,
                                       const char* dll_path);

/* Load all *.dll files from a directory. Returns count of successfully loaded. */
int akav_plugin_manager_load_dir(akav_plugin_manager_t* mgr,
                                  const char* dir_path);

/* Run all scanner plugins on a buffer. Short-circuits on first detection. */
void akav_plugin_manager_scan(const akav_plugin_manager_t* mgr,
                               const uint8_t* data, size_t data_len,
                               const akav_scan_options_t* opts,
                               akav_scan_result_t* result);

/* Shutdown all plugins and FreeLibrary. Safe to call on already-destroyed mgr. */
void akav_plugin_manager_destroy(akav_plugin_manager_t* mgr);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_PLUGIN_LOADER_H */
