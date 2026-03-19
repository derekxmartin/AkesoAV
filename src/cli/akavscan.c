/* akavscan.c -- AkesoAV CLI scanner
 * Standalone scanner. Loads engine DLL, scans files/directories, prints results.
 * JSON output. Recursive and archive-aware.
 */

#include "akesoav.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* -- EICAR test string for --eicar-test -- */
static const char EICAR_STRING[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/* -- Options -- */
typedef struct
{
    int json_output;    /* -j / --json */
    int verbose;        /* -v / --verbose */
    int recursive;      /* -r / --recursive */
    int eicar_test;     /* --eicar-test */
    int show_version;   /* --version */
    int show_help;      /* -h / --help */
    int scan_archives;  /* --archives (default on) */
    int scan_packed;    /* --packed (default on) */
    int use_heuristics; /* --heuristics (default on) */
    int heuristic_level;/* --heur-level 0-3 */
    int64_t max_filesize;/* --max-size */
    int timeout_ms;     /* --timeout */
    int file_count;
    const char* files[256];
} cli_options_t;

static void print_usage(void)
{
    fprintf(stderr,
        "AkesoAV Scanner v%s\n"
        "Usage: akavscan [options] <file|directory> [...]\n"
        "\n"
        "Options:\n"
        "  -j, --json          JSON output\n"
        "  -v, --verbose       Verbose output\n"
        "  -r, --recursive     Recurse into directories\n"
        "  --eicar-test        Self-test with EICAR string\n"
        "  --version           Show version and exit\n"
        "  -h, --help          Show this help\n"
        "  --no-archives       Disable archive scanning\n"
        "  --no-packed         Disable unpacking\n"
        "  --no-heuristics     Disable heuristic engine\n"
        "  --heur-level N      Heuristic level 0-3 (default 2=medium)\n"
        "  --max-size N        Max file size in bytes (0=no limit)\n"
        "  --timeout N         Per-file timeout in ms (default 30000)\n",
        akav_engine_version());
}

static int parse_args(int argc, char* argv[], cli_options_t* opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->scan_archives = 1;
    opts->scan_packed = 1;
    opts->use_heuristics = 1;
    opts->heuristic_level = 2;
    opts->max_filesize = 0;
    opts->timeout_ms = 30000;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0)
            opts->json_output = 1;
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            opts->verbose = 1;
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--recursive") == 0)
            opts->recursive = 1;
        else if (strcmp(argv[i], "--eicar-test") == 0)
            opts->eicar_test = 1;
        else if (strcmp(argv[i], "--version") == 0)
            opts->show_version = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            opts->show_help = 1;
        else if (strcmp(argv[i], "--no-archives") == 0)
            opts->scan_archives = 0;
        else if (strcmp(argv[i], "--no-packed") == 0)
            opts->scan_packed = 0;
        else if (strcmp(argv[i], "--no-heuristics") == 0)
            opts->use_heuristics = 0;
        else if (strcmp(argv[i], "--heur-level") == 0 && i + 1 < argc)
            opts->heuristic_level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc)
            opts->max_filesize = _atoi64(argv[++i]);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
            opts->timeout_ms = atoi(argv[++i]);
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
        else
        {
            if (opts->file_count >= 256)
            {
                fprintf(stderr, "Too many files (max 256)\n");
                return -1;
            }
            opts->files[opts->file_count++] = argv[i];
        }
    }
    return 0;
}

/* -- JSON helpers (snprintf, no external lib) -- */

static void json_escape_string(char* out, size_t out_size, const char* str)
{
    size_t j = 0;
    for (size_t i = 0; str[i] && j < out_size - 2; i++)
    {
        switch (str[i])
        {
        case '"':  if (j + 2 < out_size) { out[j++] = '\\'; out[j++] = '"'; } break;
        case '\\': if (j + 2 < out_size) { out[j++] = '\\'; out[j++] = '\\'; } break;
        case '\n': if (j + 2 < out_size) { out[j++] = '\\'; out[j++] = 'n'; } break;
        case '\r': if (j + 2 < out_size) { out[j++] = '\\'; out[j++] = 'r'; } break;
        case '\t': if (j + 2 < out_size) { out[j++] = '\\'; out[j++] = 't'; } break;
        default:   out[j++] = str[i]; break;
        }
    }
    out[j] = '\0';
}

static void print_result_json(const char* path, const akav_scan_result_t* r)
{
    char epath[1024];
    char ename[512];
    char esig[128];
    char escanner[128];
    char etype[64];
    json_escape_string(epath, sizeof(epath), path);
    json_escape_string(ename, sizeof(ename), r->malware_name);
    json_escape_string(esig, sizeof(esig), r->signature_id);
    json_escape_string(escanner, sizeof(escanner), r->scanner_id);
    json_escape_string(etype, sizeof(etype), r->file_type);

    printf("{"
           "\"path\":\"%s\","
           "\"detected\":%s,"
           "\"malware_name\":\"%s\","
           "\"signature_id\":\"%s\","
           "\"scanner_id\":\"%s\","
           "\"file_type\":\"%s\","
           "\"heuristic_score\":%.1f,"
           "\"size\":%lld,"
           "\"scan_time_ms\":%d,"
           "\"cached\":%s,"
           "\"in_whitelist\":%s,"
           "\"warning_count\":%d"
           "}\n",
           epath,
           r->found ? "true" : "false",
           ename,
           esig,
           escanner,
           etype,
           r->heuristic_score,
           (long long)r->total_size,
           r->scan_time_ms,
           r->cached ? "true" : "false",
           r->in_whitelist ? "true" : "false",
           r->warning_count);
}

static void print_result_text(const char* path, const akav_scan_result_t* r, int verbose)
{
    if (r->found)
    {
        printf("%s: DETECTED %s [%s/%s]\n", path, r->malware_name,
               r->scanner_id, r->signature_id);
    }
    else if (verbose)
    {
        printf("%s: clean (%s, %lld bytes, %dms)\n", path, r->file_type,
               (long long)r->total_size, r->scan_time_ms);
    }

    if (verbose && r->warning_count > 0)
    {
        for (int i = 0; i < r->warning_count && i < AKAV_MAX_WARNINGS; i++)
        {
            printf("  WARNING: %s\n", r->warnings[i]);
        }
    }
}

/* -- Directory scan callback -- */

typedef struct
{
    int json_output;
    int verbose;
    int infected_count;
    int scanned_count;
} scan_context_t;

static void scan_callback(const char* path, const akav_scan_result_t* result, void* user_data)
{
    scan_context_t* ctx = (scan_context_t*)user_data;
    ctx->scanned_count++;
    if (result->found)
        ctx->infected_count++;

    if (ctx->json_output)
        print_result_json(path, result);
    else
        print_result_text(path, result, ctx->verbose);
}

int main(int argc, char* argv[])
{
    cli_options_t opts;
    if (parse_args(argc, argv, &opts) != 0)
    {
        print_usage();
        return 2;
    }

    if (opts.show_help)
    {
        print_usage();
        return 0;
    }

    if (opts.show_version)
    {
        printf("AkesoAV %s\n", akav_engine_version());
        return 0;
    }

    /* Create and init engine */
    akav_engine_t* engine = NULL;
    akav_error_t err = akav_engine_create(&engine);
    if (err != AKAV_OK)
    {
        fprintf(stderr, "Failed to create engine: %s\n", akav_strerror(err));
        return 2;
    }

    err = akav_engine_init(engine, NULL);
    if (err != AKAV_OK)
    {
        fprintf(stderr, "Failed to init engine: %s\n", akav_strerror(err));
        akav_engine_destroy(engine);
        return 2;
    }

    /* --eicar-test: self-test with EICAR string */
    if (opts.eicar_test)
    {
        akav_scan_result_t result;
        akav_scan_options_t scan_opts;
        akav_scan_options_default(&scan_opts);

        err = akav_scan_buffer(engine, (const uint8_t*)EICAR_STRING,
                              strlen(EICAR_STRING), "EICAR-TEST",
                              &scan_opts, &result);
        if (err != AKAV_OK)
        {
            fprintf(stderr, "EICAR self-test FAILED: %s\n", akav_strerror(err));
            akav_engine_destroy(engine);
            return 2;
        }

        if (result.found)
        {
            if (opts.json_output)
                print_result_json("EICAR-TEST", &result);
            else
                printf("EICAR self-test PASSED: %s detected\n", result.malware_name);
            akav_engine_destroy(engine);
            return 0;
        }
        else
        {
            fprintf(stderr, "EICAR self-test FAILED: not detected\n");
            akav_engine_destroy(engine);
            return 2;
        }
    }

    /* Need at least one file/directory */
    if (opts.file_count == 0)
    {
        fprintf(stderr, "No files specified\n");
        print_usage();
        akav_engine_destroy(engine);
        return 2;
    }

    /* Build scan options */
    akav_scan_options_t scan_opts;
    akav_scan_options_default(&scan_opts);
    scan_opts.scan_archives = opts.scan_archives;
    scan_opts.scan_packed = opts.scan_packed;
    scan_opts.use_heuristics = opts.use_heuristics;
    scan_opts.heuristic_level = (akav_heur_level_t)opts.heuristic_level;
    scan_opts.max_filesize = opts.max_filesize;
    scan_opts.timeout_ms = opts.timeout_ms;

    int total_scanned = 0;
    int total_infected = 0;

    for (int i = 0; i < opts.file_count; i++)
    {
        const char* target = opts.files[i];

        /* Check if target is a directory */
        DWORD attribs = GetFileAttributesA(target);
        if (attribs == INVALID_FILE_ATTRIBUTES)
        {
            fprintf(stderr, "Cannot access: %s\n", target);
            continue;
        }

        if (attribs & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!opts.recursive)
            {
                fprintf(stderr, "Skipping directory (use -r): %s\n", target);
                continue;
            }

            scan_context_t ctx = {0};
            ctx.json_output = opts.json_output;
            ctx.verbose = opts.verbose;

            err = akav_scan_directory(engine, target, &scan_opts, scan_callback, &ctx);
            if (err != AKAV_OK)
            {
                fprintf(stderr, "Directory scan error: %s: %s\n", target, akav_strerror(err));
            }

            total_scanned += ctx.scanned_count;
            total_infected += ctx.infected_count;
        }
        else
        {
            akav_scan_result_t result;
            err = akav_scan_file(engine, target, &scan_opts, &result);
            if (err != AKAV_OK)
            {
                fprintf(stderr, "Scan error: %s: %s\n", target, akav_strerror(err));
                continue;
            }

            total_scanned++;
            if (result.found)
                total_infected++;

            if (opts.json_output)
                print_result_json(target, &result);
            else
                print_result_text(target, &result, opts.verbose);
        }
    }

    /* Summary (text mode only) */
    if (!opts.json_output && (total_scanned > 1 || opts.verbose))
    {
        printf("\n--- Scan Summary ---\n");
        printf("Scanned: %d\n", total_scanned);
        printf("Infected: %d\n", total_infected);
    }

    akav_engine_destroy(engine);

    /* Exit code: 0=clean, 1=infected, 2=error */
    return total_infected > 0 ? 1 : 0;
}
