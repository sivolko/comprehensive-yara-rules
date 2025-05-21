/*
   YARA Rule Set
   Author: Claude
   Date: 2025-05-21
   Identifier: LockBit Ransomware
   Reference: https://attack.mitre.org/software/S0726/
*/

rule ransomware_lockbit_3 {
    meta:
        description = "Detects LockBit 3.0 ransomware"
        author = "Claude"
        date = "2025-05-21"
        hash1 = "5a32eb8de90d67acdc6e6142ea91cec95e438ee2fa233135c3752ece1a1da81a"
        reference = "https://attack.mitre.org/software/S0726/"
        severity = "critical"
        
    strings:
        // File markers and strings
        $ransom_note1 = "LOCKBIT-BLOG.ONION" ascii wide
        $ransom_note2 = "lockbit" ascii wide nocase
        $ransom_note3 = ".lockbit" ascii wide
        $ransom_note4 = "restore-my-files.txt" ascii wide
        
        // Command line arguments
        $arg1 = "--encrypt" ascii wide
        $arg2 = "--nologs" ascii wide
        $arg3 = "--noshares" ascii wide
        $arg4 = "--nowasted" ascii wide
        
        // Encryption related
        $encrypt1 = { 4C 8B 11 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 89 44 24 ?? 78 ?? }
        $encrypt2 = { 48 8B 10 48 8B C8 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B D0 }
        
        // Anti-analysis techniques
        $anti1 = { 48 83 64 24 ?? 00 66 89 44 24 ?? 4C 89 7C 24 ?? 45 33 C9 }
        $anti2 = { 89 44 24 ?? 85 C0 78 ?? 48 8B 44 24 ?? 0F B7 }
        
        // Extension change
        $ext = ".lockbit" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 
        (
            // Look for ransom notes or command line arguments plus encryption code
            (2 of ($ransom_note*) and 1 of ($encrypt*)) or
            (2 of ($arg*) and 1 of ($encrypt*)) or
            // Or look for encryption routines with extension
            (all of ($encrypt*) and $ext) or
            // Or a combination of anti-analysis with other indicators
            (1 of ($anti*) and 1 of ($ransom_note*) and $ext)
        )
}