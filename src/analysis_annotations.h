#ifndef AKAV_ANALYSIS_ANNOTATIONS_H
#define AKAV_ANALYSIS_ANNOTATIONS_H

/* Cleanup APIs require initialized state and accept NULL. Keep this contract
 * visible to MSVC analysis while retaining portability for parser fuzz builds. */
#ifdef _MSC_VER
#include <sal.h>
#define AKAV_INOUT_OPT _Inout_opt_
#define AKAV_FIELD_INITIALIZED(count) _Field_size_full_opt_(count)
#else
#define AKAV_INOUT_OPT
#define AKAV_FIELD_INITIALIZED(count)
#endif

#endif
