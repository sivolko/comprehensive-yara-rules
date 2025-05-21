/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Cobalt Strike Beacon
   Reference: https://attack.mitre.org/software/S0154/
*/

rule backdoor_cobaltstrike_beacon {
    meta:
        description = "Detects Cobalt Strike Beacon malware"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        hash1 = "9b2c470c562dd0b483f4a3b640448f99a1dce7a61cc2c8a5c46a0ae2a596f61d"
        reference = "https://attack.mitre.org/software/S0154/"
        severity = "high"
        
    strings:
        // Common Beacon strings
        $beacon_str1 = "beacon.dll" nocase ascii wide
        $beacon_str2 = "beacon.x64.dll" nocase ascii wide
        $beacon_str3 = "%s (admin)" ascii wide
        $beacon_str4 = "ReflectiveLoader" ascii wide
        
        // Config & Communication
        $config1 = "%s as %s\\%s: %d" ascii wide
        $config2 = "Content-Length: %d" ascii wide
        $config3 = "Cookie: %s=%s" ascii wide
        
        // Common function stacks
        $func1 = "advapi32.dll" ascii wide
        $func2 = "CreateThread" ascii wide
        $func3 = "WaitForSingleObject" ascii wide
        $func4 = "IEX (New-Object" ascii wide
        
        // Sleep mask pattern
        $sleep_mask = { 89 ?? ?? 4C 89 ?? ?? 8D ?? ?? 41 B9 ?? ?? ?? ?? 4C 89 ?? ?? 89 ?? ?? E8 }
        
        // Public key constants
        $pk1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BF 14 B1 3D 64 0F 1F 83 }
        $pk2 = { 01 00 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        
        // HTTP related
        $http1 = "%s://%s:%d%s" ascii wide
        $http2 = "Host: %s" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 
        (
            // Look for beacon strings and functions
            (2 of ($beacon_str*) and 2 of ($func*)) or
            // Or look for sleep mask with config strings
            ($sleep_mask and 2 of ($config*)) or
            // Or look for HTTP patterns with public key constants
            (1 of ($pk*) and 2 of ($http*)) or
            // Strong detection with multiple strings
            (2 of ($beacon_str*) and 1 of ($config*) and 1 of ($http*))
        )
}