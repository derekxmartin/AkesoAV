/* test_plugin_scanner.cpp -- Test plugin DLL that detects "PLUGINTEST" string.
 *
 * This is the acceptance-criteria plugin for P6-T3:
 *   "Test plugin .dll detects 'PLUGINTEST' string."
 */

#include "plugin/plugin_loader.h"
#include <string.h>

static akav_error_t test_scan(const uint8_t* data, size_t data_len,
                               const akav_scan_options_t* /*opts*/,
                               akav_scan_result_t* result,
                               void* /*plugin_ctx*/)
{
    const char needle[] = "PLUGINTEST";
    const size_t nlen = sizeof(needle) - 1;

    for (size_t i = 0; i + nlen <= data_len; i++) {
        if (memcmp(data + i, needle, nlen) == 0) {
            result->found = 1;
            strncpy_s(result->malware_name, sizeof(result->malware_name),
                      "Test.Plugin.Detection", _TRUNCATE);
            strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                      "test_plugin", _TRUNCATE);
            strncpy_s(result->signature_id, sizeof(result->signature_id),
                      "plugin-test-1", _TRUNCATE);
            return AKAV_OK;
        }
    }

    return AKAV_OK;
}

static const akav_plugin_info_t s_plugin_info = {
    AKAV_PLUGIN_API_VERSION_MAJOR,
    AKAV_PLUGIN_API_VERSION_MINOR,
    "Test Plugin Scanner",
    "1.0.0",
    AKAV_PLUGIN_TYPE_SCANNER,
    nullptr,    /* init */
    nullptr,    /* shutdown */
    test_scan
};

extern "C" __declspec(dllexport)
const akav_plugin_info_t* akav_plugin_get_info(void)
{
    return &s_plugin_info;
}
