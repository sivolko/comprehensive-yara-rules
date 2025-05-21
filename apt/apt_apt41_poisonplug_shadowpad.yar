/*
   YARA Rule Set
   Author: Claude
   Date: 2025-05-21
   Identifier: APT41 POISONPLUG (ShadowPad) Backdoor
   Reference: https://attack.mitre.org/software/S0596/
*/

rule apt_apt41_poisonplug_shadowpad {
    meta:
        description = "Detects APT41 POISONPLUG/ShadowPad backdoor"
        author = "Claude"
        date = "2025-05-21"
        hash1 = "c4a8d5466c4f14f048e8441b382d0c12974ca4435e14e19c05b8fbe9591f5f6e"
        reference = "https://attack.mitre.org/software/S0596/"
        severity = "critical"
        
    strings:
        // DLL Exports for persistence
        $export1 = "ServiceMain" ascii wide
        $export2 = "PseudoProcess" ascii wide
        $export3 = "PseudoLdrLoadDll" ascii wide
        
        // Common strings in ShadowPad
        $str1 = "Root\\LEGACY_AMSINT" ascii wide
        $str2 = "SVCHostServiceDll" ascii wide
        $str3 = "ntsvcs.dll" ascii wide
        $str4 = "msidntld.dll" ascii wide
        $str5 = "ServiceDll" ascii wide
        
        // Command and control features
        $c2_1 = "Cookie: SESSIONID=" ascii wide
        $c2_2 = "Content-Type: application/octet-stream" ascii wide
        $c2_3 = "POST %s HTTP/1.1" ascii wide
        $c2_4 = "Connection: Keep-Alive" ascii wide
        
        // Encryption/encoding related
        $enc1 = { 35 ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? 75 ?? }
        $enc2 = { 0F B6 ?? ?? 83 ?? ?? 83 ?? ?? 33 ?? 88 ?? ?? 41 }
        $enc3 = { 8B ?? ?? ?? 8B ?? 8B ?? ?? 31 ?? 83 ?? ?? 89 ?? ?? ?? }
        
        // Loader section
        $loader1 = { 8B ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? ?? 89 ?? ?? ?? E8 }
        $loader2 = { 51 52 53 56 57 55 8B EC 83 ?? ?? 8B ?? 89 ?? ?? 8B }
        
    condition:
        uint16(0) == 0x5A4D and 
        (
            // Look for exports and strings
            (1 of ($export*) and 2 of ($str*)) or
            // Or look for C2 capability with encryption
            (2 of ($c2*) and 1 of ($enc*)) or
            // Or loader with strings
            (1 of ($loader*) and 2 of ($str*)) or
            // Strong detection with multiple indicators
            (1 of ($export*) and 1 of ($str*) and 1 of ($c2*) and 1 of ($enc*))
        )
}