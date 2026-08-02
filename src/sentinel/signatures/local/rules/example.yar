/*
    Sentinel Scan — bundled example rules.

    These ship with the package so a fresh install has something to match on
    before the first `sentinel update`. They are deliberately conservative:
    a desktop scanner that cries wolf gets uninstalled.

    Metadata this project understands:

      confidence  0-100. Overrides the tag-derived value. Use it.
      severity    critical | high | medium | low | info
      description Shown to the user. Write it for a non-specialist.
      author, reference, date  Provenance.

    Tags are used as a fallback when `confidence` is absent — see
    _TAG_CONFIDENCE in engine/detectors/yara_detector.py.

    See docs/writing-detectors.md for the full guide.
*/

rule Sentinel_EICAR_Test_File : info
{
    meta:
        description  = "The EICAR anti-malware test file. Harmless by design — it exists so you can verify a scanner works."
        confidence   = 85
        severity     = "medium"
        author       = "Sentinel Scan"
        reference    = "https://www.eicar.org/download-anti-malware-testfile/"
        threat_name  = "EICAR-Test-File"

    strings:
        // Split so this rule file does not itself trip other scanners.
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule Sentinel_PowerShell_Encoded_Dropper : malware
{
    meta:
        description  = "PowerShell invoked with a base64-encoded command and a hidden window — the standard shape of a script dropper."
        confidence   = 75
        severity     = "high"
        author       = "Sentinel Scan"
        threat_name  = "Heuristic.PowerShell.EncodedDropper"

    strings:
        $ps        = "powershell" nocase
        $enc1      = "-encodedcommand" nocase
        $enc2      = "-enc " nocase
        $enc3      = "-e " nocase
        $hidden    = "-windowstyle hidden" nocase
        $bypass    = "-executionpolicy bypass" nocase
        $noprofile = "-nop" nocase

    condition:
        $ps
        and any of ($enc*)
        and any of ($hidden, $bypass, $noprofile)
}

rule Sentinel_Ransomware_Recovery_Destruction : ransomware
{
    meta:
        description  = "Deletes volume shadow copies and disables Windows recovery. Ransomware does this immediately before encrypting; almost nothing legitimate does it at all."
        confidence   = 90
        severity     = "critical"
        author       = "Sentinel Scan"
        threat_name  = "Heuristic.Ransomware.RecoveryDestruction"

    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin.exe delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
        $bcd  = "bcdedit /set {default} recoveryenabled no" nocase
        $bcd2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $wbadmin = "wbadmin delete catalog" nocase

    condition:
        2 of them
}

rule Sentinel_Credential_Dumper : malware
{
    meta:
        description  = "Contains command strings from credential-dumping tooling."
        confidence   = 85
        severity     = "critical"
        author       = "Sentinel Scan"
        threat_name  = "Heuristic.CredentialDumper"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "sekurlsa::wdigest" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "lsadump::dcsync" nocase
        $s5 = "privilege::debug" nocase
        $s6 = "Invoke-Mimikatz" nocase

    condition:
        any of them
}

rule Sentinel_Suspicious_LOLBin_Download : suspicious
{
    meta:
        description  = "Uses a built-in Windows utility to download a file — a common way to fetch a payload without touching a browser or PowerShell."
        confidence   = 55
        severity     = "medium"
        author       = "Sentinel Scan"
        threat_name  = "Heuristic.LOLBin.Download"

    strings:
        $certutil = "certutil -urlcache" nocase
        $certutil2 = "certutil.exe -urlcache" nocase
        $bits     = "bitsadmin /transfer" nocase
        $mshta    = "mshta http" nocase
        $regsvr   = "regsvr32 /s /u /i:http" nocase

    condition:
        any of them
}

rule Sentinel_UPX_Packed : packer
{
    meta:
        description  = "Packed with UPX. Extremely common in both legitimate software and malware — informational only, and scored accordingly."
        confidence   = 15
        severity     = "low"
        author       = "Sentinel Scan"
        threat_name  = "Packer.UPX"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx  = "UPX!"

    condition:
        uint16(0) == 0x5A4D and 2 of them
}
