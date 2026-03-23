// test_pdf.cpp -- Tests for PDF parser (P7-T2).
//
// Tests cover:
//   - Basic PDF parsing (traditional xref)
//   - FlateDecode stream decompression (EICAR in stream)
//   - ASCII85Decode, ASCIIHexDecode, LZWDecode
//   - Multi-filter chain
//   - JS extraction via /OpenAction
//   - Incremental xref (multiple tables)
//   - Malformed xref (error not crash)
//   - Non-PDF data returns false
//   - Truncated / empty input

#include <gtest/gtest.h>
#include "parsers/pdf.h"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <zlib.h>

// ── PDF Builder ───────────────────────────────────────────────────

// Helper to construct minimal valid PDF files for testing.
class PdfBuilder {
public:
    struct ObjDef {
        uint32_t num;
        uint32_t gen;
        std::string content; // includes stream if any
    };

    std::vector<ObjDef> objects;
    uint32_t next_obj = 1;

    uint32_t add_obj(const std::string& content, uint32_t gen = 0) {
        uint32_t num = next_obj++;
        objects.push_back({ num, gen, content });
        return num;
    }

    // Build a complete PDF with traditional xref table
    std::vector<uint8_t> build(uint32_t catalog_obj = 0) {
        std::string pdf;
        pdf += "%PDF-1.7\n";

        // Write objects, recording offsets
        std::vector<std::pair<uint32_t, size_t>> offsets; // (obj_num, offset)

        for (auto& obj : objects) {
            offsets.push_back({ obj.num, pdf.size() });
            pdf += std::to_string(obj.num) + " " + std::to_string(obj.gen) + " obj\n";
            pdf += obj.content + "\n";
            pdf += "endobj\n\n";
        }

        // Xref table
        size_t xref_offset = pdf.size();
        pdf += "xref\n";

        // Find max obj num
        uint32_t max_obj = 0;
        for (auto& p : offsets)
            if (p.first > max_obj) max_obj = p.first;

        pdf += "0 " + std::to_string(max_obj + 1) + "\n";

        // Entry for obj 0 (free)
        pdf += "0000000000 65535 f \n";

        // Entries for objects
        for (uint32_t i = 1; i <= max_obj; i++) {
            bool found = false;
            for (auto& p : offsets) {
                if (p.first == i) {
                    char entry[22];
                    snprintf(entry, sizeof(entry), "%010zu 00000 n \n", p.second);
                    pdf += entry;
                    found = true;
                    break;
                }
            }
            if (!found) {
                pdf += "0000000000 00000 f \n";
            }
        }

        // Trailer
        if (catalog_obj == 0 && !objects.empty())
            catalog_obj = objects[0].num;

        pdf += "trailer\n";
        pdf += "<< /Size " + std::to_string(max_obj + 1);
        pdf += " /Root " + std::to_string(catalog_obj) + " 0 R >>\n";
        pdf += "startxref\n";
        pdf += std::to_string(xref_offset) + "\n";
        pdf += "%%EOF\n";

        return std::vector<uint8_t>(pdf.begin(), pdf.end());
    }
};

// Helper to compress data with zlib (for FlateDecode streams)
static std::vector<uint8_t> zlib_compress(const uint8_t* data, size_t len)
{
    uLongf dest_len = compressBound((uLong)len);
    std::vector<uint8_t> compressed(dest_len);
    int ret = compress(compressed.data(), &dest_len, data, (uLong)len);
    if (ret != Z_OK) return {};
    compressed.resize(dest_len);
    return compressed;
}

// Build a stream object string with given content and filter
static std::string make_stream_obj(const std::string& dict_extra,
                                    const uint8_t* stream_data, size_t stream_len)
{
    std::string s = "<< /Length " + std::to_string(stream_len);
    if (!dict_extra.empty()) s += " " + dict_extra;
    s += " >>\nstream\n";
    s.append((const char*)stream_data, stream_len);
    s += "\nendstream";
    return s;
}

// ── Basic parsing tests ───────────────────────────────────────────

TEST(PDFParse, BasicTraditionalXref)
{
    PdfBuilder pb;
    uint32_t catalog = pb.add_obj("<< /Type /Catalog /Pages 2 0 R >>");
    pb.add_obj("<< /Type /Pages /Count 0 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    EXPECT_TRUE(pdf.valid);
    EXPECT_EQ(pdf.major_version, 1);
    EXPECT_EQ(pdf.minor_version, 7);
    EXPECT_GT(pdf.num_objects, 0u);
    EXPECT_EQ(pdf.catalog_obj, catalog);

    akav_pdf_free(&pdf);
}

TEST(PDFParse, VersionDetected)
{
    PdfBuilder pb;
    pb.add_obj("<< /Type /Catalog >>");
    auto data = pb.build();

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    EXPECT_EQ(pdf.major_version, 1);
    EXPECT_EQ(pdf.minor_version, 7);

    akav_pdf_free(&pdf);
}

// ── Filter decoder tests ──────────────────────────────────────────

TEST(PDFFlate, DecompressEICAR)
{
    const char EICAR[] =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t eicar_len = 68;

    auto compressed = zlib_compress((const uint8_t*)EICAR, eicar_len);
    ASSERT_GT(compressed.size(), 0u);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_flate(compressed.data(), compressed.size(),
                                       &out, &out_len));
    ASSERT_EQ(out_len, eicar_len);
    EXPECT_EQ(memcmp(out, EICAR, eicar_len), 0);
    free(out);
}

TEST(PDFFlate, EmptyInput)
{
    uint8_t* out = nullptr;
    size_t out_len = 0;
    EXPECT_FALSE(akav_pdf_decode_flate(nullptr, 0, &out, &out_len));
}

TEST(PDFASCII85, DecodeFull)
{
    // "Hello" encoded in ASCII85 = "87cURD]j7BEbo7~>"
    const char* encoded = "87cURD]j7BEbo7~>";
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_ascii85((const uint8_t*)encoded, strlen(encoded),
                                         &out, &out_len));
    // ASCII85("Hello") should decode back
    EXPECT_GE(out_len, 5u);
    std::string result((char*)out, out_len);
    EXPECT_NE(result.find("Hello"), std::string::npos);
    free(out);
}

TEST(PDFASCII85, ZeroShortcut)
{
    // 'z' encodes four zero bytes
    const char* encoded = "z~>";
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_ascii85((const uint8_t*)encoded, strlen(encoded),
                                         &out, &out_len));
    ASSERT_EQ(out_len, 4u);
    EXPECT_EQ(out[0], 0); EXPECT_EQ(out[1], 0);
    EXPECT_EQ(out[2], 0); EXPECT_EQ(out[3], 0);
    free(out);
}

TEST(PDFASCIIHex, DecodeBasic)
{
    const char* encoded = "48656C6C6F>";
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_asciihex((const uint8_t*)encoded, strlen(encoded),
                                          &out, &out_len));
    ASSERT_EQ(out_len, 5u);
    EXPECT_EQ(memcmp(out, "Hello", 5), 0);
    free(out);
}

TEST(PDFASCIIHex, OddNibble)
{
    // Trailing odd nibble should be padded with 0
    const char* encoded = "4>";
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_asciihex((const uint8_t*)encoded, strlen(encoded),
                                          &out, &out_len));
    ASSERT_EQ(out_len, 1u);
    EXPECT_EQ(out[0], 0x40);
    free(out);
}

TEST(PDFLZW, DecompressSimple)
{
    // Use ASCIIHex encode then LZW decode round-trip via a known good encoding.
    // Simpler approach: just verify LZW decodes *something* from a valid stream
    // and that clear/EOD codes work.
    //
    // Build stream manually: clear(256), 'H'(72), 'i'(105), EOD(257)
    // All 9-bit codes, MSB first.
    //
    // Bits: 100000000  001001000  001101001  100000001
    //       clear=256  'H'=72     'i'=105    EOD=257
    //
    // Concatenated: 100000000 001001000 001101001 100000001
    // Bytes (MSB first):
    //   [0] bits 0-7:   10000000 = 0x80
    //   [1] bits 8-15:  00010010 = 0x12
    //   [2] bits 16-23: 00001101 = 0x0D
    //   [3] bits 24-31: 00110000 = 0x30
    //   [4] bits 32-35: 0001xxxx = 0x10

    uint8_t lzw_data[] = { 0x80, 0x12, 0x0D, 0x30, 0x10 };

    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decode_lzw(lzw_data, sizeof(lzw_data), &out, &out_len));
    ASSERT_EQ(out_len, 2u);
    EXPECT_EQ(out[0], 'H');
    EXPECT_EQ(out[1], 'i');
    free(out);
}

// ── Multi-filter chain test ───────────────────────────────────────

TEST(PDFFilters, ChainFlateASCIIHex)
{
    // Encode "TestData" as ASCIIHex, then compress with Flate.
    // Chain: [/FlateDecode /ASCIIHexDecode]
    // Meaning: first apply FlateDecode, then ASCIIHexDecode to the result.

    // So the stream is: flate_compress(asciihex_encode("TestData"))
    const char* text = "TestData";
    // ASCIIHex encode
    std::string hex_encoded;
    for (size_t i = 0; i < strlen(text); i++) {
        char h[3];
        snprintf(h, sizeof(h), "%02X", (uint8_t)text[i]);
        hex_encoded += h;
    }
    hex_encoded += ">";

    auto compressed = zlib_compress((const uint8_t*)hex_encoded.c_str(), hex_encoded.size());
    ASSERT_GT(compressed.size(), 0u);

    akav_pdf_filter_t filters[] = { AKAV_PDF_FILTER_FLATE, AKAV_PDF_FILTER_ASCIIHEX };
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decompress_stream(compressed.data(), compressed.size(),
                                            filters, 2, &out, &out_len));
    ASSERT_EQ(out_len, strlen(text));
    EXPECT_EQ(memcmp(out, text, out_len), 0);
    free(out);
}

TEST(PDFFilters, NoFilter)
{
    const char* text = "raw stream data";
    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_pdf_decompress_stream((const uint8_t*)text, strlen(text),
                                            nullptr, 0, &out, &out_len));
    ASSERT_EQ(out_len, strlen(text));
    EXPECT_EQ(memcmp(out, text, out_len), 0);
    free(out);
}

// ── Stream in PDF object tests ────────────────────────────────────

TEST(PDFStream, FlateDecodeEICAR)
{
    // Build a PDF with a FlateDecode stream containing EICAR
    const char EICAR[] =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t eicar_len = 68;

    auto compressed = zlib_compress((const uint8_t*)EICAR, eicar_len);
    ASSERT_GT(compressed.size(), 0u);

    PdfBuilder pb;
    uint32_t catalog = pb.add_obj("<< /Type /Catalog /Pages 2 0 R >>");
    pb.add_obj("<< /Type /Pages /Count 0 >>");
    std::string stream_obj = make_stream_obj("/Filter /FlateDecode",
                                              compressed.data(), compressed.size());
    pb.add_obj(stream_obj);

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    EXPECT_TRUE(pdf.valid);
    EXPECT_GE(pdf.num_objects, 3u);

    akav_pdf_free(&pdf);
}

// ── JavaScript extraction tests ───────────────────────────────────

TEST(PDFJS, ExtractFromOpenAction)
{
    PdfBuilder pb;
    // Catalog with /OpenAction containing JS
    uint32_t action = pb.add_obj(
        "<< /Type /Action /S /JavaScript /JS (app.alert\\('test'\\)) >>"
    );
    uint32_t catalog = pb.add_obj(
        "<< /Type /Catalog /Pages 3 0 R /OpenAction " +
        std::to_string(action) + " 0 R >>"
    );
    pb.add_obj("<< /Type /Pages /Count 0 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    ASSERT_TRUE(akav_pdf_extract_js(&pdf, data.data(), data.size()));

    EXPECT_TRUE(pdf.has_javascript);
    EXPECT_TRUE(pdf.has_open_action);
    ASSERT_GE(pdf.num_js, 1u);

    std::string js((char*)pdf.js_entries[0].data, pdf.js_entries[0].data_len);
    EXPECT_NE(js.find("app.alert"), std::string::npos);

    akav_pdf_free(&pdf);
}

TEST(PDFJS, InlineOpenActionJS)
{
    PdfBuilder pb;
    // Catalog with inline /OpenAction dictionary
    uint32_t catalog = pb.add_obj(
        "<< /Type /Catalog /Pages 2 0 R "
        "/OpenAction << /S /JavaScript /JS (malicious_code\\(\\)) >> >>"
    );
    pb.add_obj("<< /Type /Pages /Count 0 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    ASSERT_TRUE(akav_pdf_extract_js(&pdf, data.data(), data.size()));

    EXPECT_TRUE(pdf.has_javascript);
    ASSERT_GE(pdf.num_js, 1u);
    std::string js((char*)pdf.js_entries[0].data, pdf.js_entries[0].data_len);
    EXPECT_NE(js.find("malicious_code"), std::string::npos);

    akav_pdf_free(&pdf);
}

TEST(PDFJS, NoJSInCleanPDF)
{
    PdfBuilder pb;
    uint32_t catalog = pb.add_obj("<< /Type /Catalog /Pages 2 0 R >>");
    pb.add_obj("<< /Type /Pages /Count 0 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    akav_pdf_extract_js(&pdf, data.data(), data.size());

    EXPECT_FALSE(pdf.has_javascript);
    EXPECT_EQ(pdf.num_js, 0u);

    akav_pdf_free(&pdf);
}

// ── Suspicious indicator tests ────────────────────────────────────

TEST(PDFAnalyze, EncryptionDetected)
{
    PdfBuilder pb;
    uint32_t catalog = pb.add_obj("<< /Type /Catalog /Pages 2 0 R >>");
    pb.add_obj("<< /Type /Pages /Count 0 >>");
    pb.add_obj("<< /Type /Encrypt /Filter /Standard /V 4 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    akav_pdf_analyze(&pdf, data.data(), data.size());

    EXPECT_TRUE(pdf.has_encrypted);

    akav_pdf_free(&pdf);
}

TEST(PDFAnalyze, LaunchDetected)
{
    PdfBuilder pb;
    uint32_t action = pb.add_obj("<< /Type /Action /S /Launch /F (cmd.exe) >>");
    uint32_t catalog = pb.add_obj(
        "<< /Type /Catalog /Pages 3 0 R /OpenAction " +
        std::to_string(action) + " 0 R >>"
    );
    pb.add_obj("<< /Type /Pages /Count 0 >>");

    auto data = pb.build(catalog);

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, data.data(), data.size()));
    akav_pdf_analyze(&pdf, data.data(), data.size());

    EXPECT_TRUE(pdf.has_launch_action);

    akav_pdf_free(&pdf);
}

// ── Error handling tests ──────────────────────────────────────────

TEST(PDFParse, NullInput)
{
    akav_pdf_t pdf;
    EXPECT_FALSE(akav_pdf_parse(&pdf, nullptr, 0));
    EXPECT_FALSE(pdf.valid);
}

TEST(PDFParse, NullPdfStruct)
{
    uint8_t data[] = "%PDF-1.0";
    EXPECT_FALSE(akav_pdf_parse(nullptr, data, sizeof(data)));
}

TEST(PDFParse, TooSmall)
{
    uint8_t data[] = "%PDF";
    akav_pdf_t pdf;
    EXPECT_FALSE(akav_pdf_parse(&pdf, data, 4));
}

TEST(PDFParse, NonPDFData)
{
    uint8_t data[] = "This is not a PDF file at all, just random text";
    akav_pdf_t pdf;
    EXPECT_FALSE(akav_pdf_parse(&pdf, data, sizeof(data)));
    EXPECT_FALSE(pdf.valid);
}

TEST(PDFParse, NoStartxref)
{
    const char* broken = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
    akav_pdf_t pdf;
    EXPECT_FALSE(akav_pdf_parse(&pdf, (const uint8_t*)broken, strlen(broken)));
}

TEST(PDFParse, MalformedXref)
{
    // Valid header + startxref pointing to garbage
    std::string s = "%PDF-1.7\ngarbage garbage garbage\n";
    s += "startxref\n5\n%%EOF\n";  // offset 5 = inside "garbage"

    akav_pdf_t pdf;
    EXPECT_FALSE(akav_pdf_parse(&pdf, (const uint8_t*)s.c_str(), s.size()));

    akav_pdf_free(&pdf);
}

// ── Free safety tests ─────────────────────────────────────────────

TEST(PDFFree, NullSafe)
{
    akav_pdf_free(nullptr);
}

TEST(PDFFree, DoubleFree)
{
    akav_pdf_t pdf;
    memset(&pdf, 0, sizeof(pdf));
    akav_pdf_free(&pdf);
    akav_pdf_free(&pdf);
}

// ── Incremental xref test ─────────────────────────────────────────

TEST(PDFParse, IncrementalXref)
{
    // Build a PDF with two xref tables (simulating an incremental update)
    std::string s;
    s += "%PDF-1.7\n";

    // Object 1
    size_t obj1_off = s.size();
    s += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\n";

    // Object 2
    size_t obj2_off = s.size();
    s += "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n\n";

    // First xref table
    size_t xref1_off = s.size();
    s += "xref\n";
    s += "0 3\n";
    s += "0000000000 65535 f \n";
    char entry[22];
    snprintf(entry, sizeof(entry), "%010zu 00000 n \n", obj1_off);
    s += entry;
    snprintf(entry, sizeof(entry), "%010zu 00000 n \n", obj2_off);
    s += entry;
    s += "trailer\n<< /Size 3 /Root 1 0 R >>\n";
    s += "startxref\n" + std::to_string(xref1_off) + "\n%%EOF\n";

    // Incremental update: add object 3
    size_t obj3_off = s.size();
    s += "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\n";

    // Second xref table
    size_t xref2_off = s.size();
    s += "xref\n";
    s += "3 1\n";
    snprintf(entry, sizeof(entry), "%010zu 00000 n \n", obj3_off);
    s += entry;
    s += "trailer\n<< /Size 4 /Root 1 0 R /Prev " +
         std::to_string(xref1_off) + " >>\n";
    s += "startxref\n" + std::to_string(xref2_off) + "\n%%EOF\n";

    akav_pdf_t pdf;
    ASSERT_TRUE(akav_pdf_parse(&pdf, (const uint8_t*)s.c_str(), s.size()));
    EXPECT_TRUE(pdf.valid);
    EXPECT_GE(pdf.num_xref_tables, 2u);
    EXPECT_GE(pdf.num_objects, 4u); // 0 (free) + 1,2,3

    akav_pdf_free(&pdf);
}
