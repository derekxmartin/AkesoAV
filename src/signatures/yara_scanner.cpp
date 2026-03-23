/* yara_scanner.cpp -- YARA rule matching integration (P9-T1).
 *
 * Compiles YARA rules from source text stored in the .akavdb
 * YARA section, then scans buffers against compiled rules.
 */

#include "signatures/yara_scanner.h"

/* Suppress warnings from YARA third-party headers */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4324)  /* structure was padded due to alignment */
#endif
#include <yara.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <string.h>
#include <stdio.h>

/* ── Global init/cleanup ─────────────────────────────────────────── */

bool akav_yara_global_init(void)
{
    int rc = yr_initialize();
    return (rc == ERROR_SUCCESS);
}

void akav_yara_global_cleanup(void)
{
    yr_finalize();
}

/* ── Scanner init/destroy ────────────────────────────────────────── */

void akav_yara_scanner_init(akav_yara_scanner_t* scanner)
{
    if (!scanner) return;
    memset(scanner, 0, sizeof(*scanner));
}

void akav_yara_scanner_destroy(akav_yara_scanner_t* scanner)
{
    if (!scanner) return;

    if (scanner->rules) {
        yr_rules_destroy((YR_RULES*)scanner->rules);
        scanner->rules = NULL;
    }
    scanner->loaded = false;
    scanner->rule_count = 0;
    scanner->compile_error[0] = '\0';
}

/* ── Compilation error callback ──────────────────────────────────── */

typedef struct {
    char* buf;
    size_t buf_size;
} compile_error_ctx_t;

static void compile_error_callback(int error_level,
                                    const char* file_name,
                                    int line_number,
                                    const YR_RULE* rule,
                                    const char* message,
                                    void* user_data)
{
    (void)rule;
    compile_error_ctx_t* ctx = (compile_error_ctx_t*)user_data;
    if (!ctx || !ctx->buf || ctx->buf_size == 0) return;

    /* Only capture the first error */
    if (ctx->buf[0] != '\0') return;

    const char* level = (error_level == YARA_ERROR_LEVEL_ERROR) ? "error" : "warning";
    const char* fname = file_name ? file_name : "<rules>";

    snprintf(ctx->buf, ctx->buf_size, "%s(%d): %s: %s",
             fname, line_number, level, message);
}

/* ── Load rules from source ──────────────────────────────────────── */

bool akav_yara_load_source(akav_yara_scanner_t* scanner,
                            const char* source, size_t source_len)
{
    if (!scanner || !source || source_len == 0)
        return false;

    /* Destroy previous rules if reloading */
    if (scanner->rules) {
        yr_rules_destroy((YR_RULES*)scanner->rules);
        scanner->rules = NULL;
        scanner->loaded = false;
        scanner->rule_count = 0;
    }
    scanner->compile_error[0] = '\0';

    /* Create compiler */
    YR_COMPILER* compiler = NULL;
    int rc = yr_compiler_create(&compiler);
    if (rc != ERROR_SUCCESS) {
        snprintf(scanner->compile_error, sizeof(scanner->compile_error),
                 "yr_compiler_create failed: %d", rc);
        return false;
    }

    /* Set error callback */
    compile_error_ctx_t err_ctx;
    err_ctx.buf = scanner->compile_error;
    err_ctx.buf_size = sizeof(scanner->compile_error);
    yr_compiler_set_callback(compiler, compile_error_callback, &err_ctx);

    /* Compile source — need to ensure null-termination */
    char* source_copy = NULL;
    bool need_copy = (source[source_len] != '\0');
    if (need_copy) {
        source_copy = (char*)malloc(source_len + 1);
        if (!source_copy) {
            yr_compiler_destroy(compiler);
            snprintf(scanner->compile_error, sizeof(scanner->compile_error),
                     "out of memory");
            return false;
        }
        memcpy(source_copy, source, source_len);
        source_copy[source_len] = '\0';
    }

    const char* src = source_copy ? source_copy : source;
    int errors = yr_compiler_add_string(compiler, src, NULL);
    free(source_copy);

    if (errors > 0) {
        yr_compiler_destroy(compiler);
        /* compile_error already set by callback */
        if (scanner->compile_error[0] == '\0') {
            snprintf(scanner->compile_error, sizeof(scanner->compile_error),
                     "%d compilation error(s)", errors);
        }
        return false;
    }

    /* Get compiled rules */
    YR_RULES* rules = NULL;
    rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    if (rc != ERROR_SUCCESS || !rules) {
        snprintf(scanner->compile_error, sizeof(scanner->compile_error),
                 "yr_compiler_get_rules failed: %d", rc);
        return false;
    }

    /* Count rules */
    uint32_t count = 0;
    YR_RULE* rule;
    yr_rules_foreach(rules, rule) {
        count++;
    }

    scanner->rules = rules;
    scanner->loaded = true;
    scanner->rule_count = count;
    return true;
}

/* ── Load from .akavdb section ───────────────────────────────────── */

bool akav_yara_load_section(akav_yara_scanner_t* scanner,
                             const uint8_t* section_data,
                             size_t section_size)
{
    if (!scanner || !section_data || section_size == 0)
        return false;

    /* The YARA section stores rule source as a UTF-8 blob */
    return akav_yara_load_source(scanner,
                                  (const char*)section_data,
                                  section_size);
}

/* ── Scan callback ───────────────────────────────────────────────── */

typedef struct {
    akav_yara_match_t* match;
} scan_ctx_t;

static int scan_callback(YR_SCAN_CONTEXT* context,
                          int message,
                          void* message_data,
                          void* user_data)
{
    (void)context;
    scan_ctx_t* ctx = (scan_ctx_t*)user_data;
    if (!ctx || !ctx->match) return CALLBACK_ABORT;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        ctx->match->match_count++;

        /* Capture first match details */
        if (!ctx->match->matched) {
            ctx->match->matched = true;
            strncpy_s(ctx->match->rule_name, sizeof(ctx->match->rule_name),
                      rule->identifier, _TRUNCATE);

            const char* ns = rule->ns ? rule->ns->name : "default";
            strncpy_s(ctx->match->rule_ns, sizeof(ctx->match->rule_ns),
                      ns, _TRUNCATE);
        }
    }

    return CALLBACK_CONTINUE;
}

/* ── Scan buffer ─────────────────────────────────────────────────── */

bool akav_yara_scan_buffer(const akav_yara_scanner_t* scanner,
                            const uint8_t* data, size_t data_len,
                            akav_yara_match_t* match)
{
    if (!scanner || !scanner->loaded || !scanner->rules)
        return false;
    if (!data || data_len == 0 || !match)
        return false;

    memset(match, 0, sizeof(*match));

    scan_ctx_t ctx;
    ctx.match = match;

    int rc = yr_rules_scan_mem((YR_RULES*)scanner->rules,
                                data, data_len,
                                0,  /* flags */
                                scan_callback, &ctx,
                                AKAV_YARA_SCAN_TIMEOUT);

    if (rc != ERROR_SUCCESS && rc != ERROR_SCAN_TIMEOUT) {
        return false;
    }

    return match->matched;
}
