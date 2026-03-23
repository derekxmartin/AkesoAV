/* test_plugin_bad_version.cpp -- Plugin DLL with wrong API version.
 *
 * Used to test that the engine skips plugins with incompatible API versions.
 * Reports api_version_major=99, which the loader should reject.
 */

#include "plugin/plugin_loader.h"

static const akav_plugin_info_t s_bad_info = {
    99,     /* api_version_major -- deliberately wrong */
    0,      /* api_version_minor */
    "Bad Version Plugin",
    "1.0.0",
    AKAV_PLUGIN_TYPE_SCANNER,
    nullptr,
    nullptr,
    nullptr
};

extern "C" __declspec(dllexport)
const akav_plugin_info_t* akav_plugin_get_info(void)
{
    return &s_bad_info;
}
