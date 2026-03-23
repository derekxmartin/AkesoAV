/* fuzz_pdf.cpp — libFuzzer target for PDF parser.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Feeds arbitrary bytes into the PDF parser (core parse, JS extraction,
 * embedded file extraction, stream decompression, analysis) to find
 * crashes, hangs, or memory errors.
 */

#include "parsers/pdf.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    akav_pdf_t pdf;
    memset(&pdf, 0, sizeof(pdf));

    /* Core parse: header, xref, trailer, object catalog */
    if (!akav_pdf_parse(&pdf, data, size)) {
        akav_pdf_free(&pdf);
        return 0;
    }

    /* JavaScript extraction */
    akav_pdf_extract_js(&pdf, data, size);

    /* Embedded file extraction */
    akav_pdf_extract_embedded(&pdf, data, size);

    /* Full analysis (suspicious patterns, anomalies) */
    akav_pdf_analyze(&pdf, data, size);

    /* Exercise stream decompression on first few objects if they exist */
    for (uint32_t i = 0; i < pdf.num_objects && i < 10; i++) {
        if (pdf.objects[i].stream_offset > 0 && pdf.objects[i].stream_len > 0 &&
            pdf.objects[i].stream_offset + pdf.objects[i].stream_len <= size) {
            uint8_t* out = nullptr;
            size_t out_len = 0;

            /* Try FlateDecode */
            akav_pdf_filter_t filter;
            memset(&filter, 0, sizeof(filter));
            filter.type = AKAV_PDF_FILTER_FLATE;
            akav_pdf_decompress_stream(
                data + pdf.objects[i].stream_offset,
                pdf.objects[i].stream_len,
                &filter, 1, &out, &out_len);
            free(out);

            /* Try ASCII85 */
            out = nullptr;
            out_len = 0;
            filter.type = AKAV_PDF_FILTER_ASCII85;
            akav_pdf_decompress_stream(
                data + pdf.objects[i].stream_offset,
                pdf.objects[i].stream_len,
                &filter, 1, &out, &out_len);
            free(out);
        }
    }

    /* Also fuzz standalone decoders directly */
    {
        uint8_t* out = nullptr;
        size_t out_len = 0;

        akav_pdf_decode_flate(data, size, &out, &out_len);
        free(out);

        out = nullptr; out_len = 0;
        akav_pdf_decode_ascii85(data, size, &out, &out_len);
        free(out);

        out = nullptr; out_len = 0;
        akav_pdf_decode_asciihex(data, size, &out, &out_len);
        free(out);

        out = nullptr; out_len = 0;
        akav_pdf_decode_lzw(data, size, &out, &out_len);
        free(out);
    }

    akav_pdf_free(&pdf);
    return 0;
}
