/*
   YARA Rule Set
   Author: Claude
   Date: 2025-05-21
   Identifier: Raccoon Stealer Malware
   Reference: https://attack.mitre.org/software/S0413/
*/

rule infostealer_raccoon_v2 {
    meta:
        description = "Detects Raccoon Stealer v2 malware"
        author = "Claude"
        date = "2025-05-21"
        hash1 = "a9efd0ae841ae3fb4e7f85af8780f90ea9561a642baa7de53a54d03d5686e70b"
        reference = "https://attack.mitre.org/software/S0413/"
        severity = "high"
        
    strings:
        // Common strings found in Raccoon
        $str1 = "Raccoon Stealer" ascii wide nocase
        $str2 = "raccoon" ascii wide nocase
        $str3 = "recenv" ascii wide
        
        // Browser targeting
        $browser1 = "\\Mozilla\\Firefox\\Profiles\\" ascii wide
        $browser2 = "\\Google\\Chrome\\User Data\\" ascii wide
        $browser3 = "\\Chromium\\User Data\\" ascii wide
        $browser4 = "Opera Software" ascii wide
        $browser5 = "logins.json" ascii wide
        $browser6 = "Login Data" ascii wide
        
        // Cryptocurrency stealing
        $crypto1 = "wallet.dat" ascii wide
        $crypto2 = "\\Ethereum\\keystore\\" ascii wide
        $crypto3 = "\\Bitcoin\\wallets\\" ascii wide
        $crypto4 = "Electrum" ascii wide
        
        // C2 communication
        $c2_1 = "gate.php" ascii wide
        $c2_2 = "config.php" ascii wide
        $c2_3 = "POST" ascii wide
        $c2_4 = "Content-Type: application/x-www-form-urlencoded" ascii wide
        
        // System info collection
        $sys1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor" ascii wide
        $sys2 = "PROCESSOR_IDENTIFIER" ascii wide
        $sys3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii wide
        
        // File patterns
        $file1 = ".zip" ascii wide
        $file2 = { 50 4B 03 04 } // ZIP header  
        
    condition:
        uint16(0) == 0x5A4D and 
        (
            // Look for Raccoon strings plus browser or crypto targeting
            ((1 of ($str*)) and (3 of ($browser*) or 2 of ($crypto*))) or
            // Or look for system info collection with C2 communication
            (2 of ($sys*) and 2 of ($c2*)) or
            // Strong detection with multiple indicators
            (1 of ($str*) and 2 of ($browser*) and 1 of ($crypto*) and 1 of ($c2*))
        )
}