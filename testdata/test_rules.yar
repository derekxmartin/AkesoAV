/* test_rules.yar -- Test YARA rules for AkesoAV unit tests */

rule EICAR_Test_File {
    meta:
        description = "Detects EICAR test file via YARA"
        author = "AkesoAV"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_MZ_Header {
    meta:
        description = "Detects MZ header (PE files)"
        author = "AkesoAV"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
