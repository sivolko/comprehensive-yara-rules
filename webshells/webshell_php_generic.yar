/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: PHP Web Shells
   Reference: Common PHP webshell patterns
*/

rule webshell_php_generic {
    meta:
        description = "Detects generic PHP webshells with common patterns"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/"
        severity = "high"
        
    strings:
        // Function execution indicators
        $func_exec1 = "exec(" nocase ascii wide
        $func_exec2 = "shell_exec(" nocase ascii wide
        $func_exec3 = "system(" nocase ascii wide
        $func_exec4 = "passthru(" nocase ascii wide 
        $func_exec5 = "popen(" nocase ascii wide
        $func_exec6 = "proc_open(" nocase ascii wide
        
        // Input indicators
        $input1 = "$_GET[" nocase ascii wide
        $input2 = "$_POST[" nocase ascii wide
        $input3 = "$_REQUEST[" nocase ascii wide
        $input4 = "$_COOKIE[" nocase ascii wide
        
        // Obfuscation indicators
        $obf1 = "base64_decode(" nocase ascii wide
        $obf2 = "gzinflate(" nocase ascii wide
        $obf3 = "eval(" nocase ascii wide
        $obf4 = "str_rot13(" nocase ascii wide
        $obf5 = "gzuncompress(" nocase ascii wide
        $obf6 = "strrev(" nocase ascii wide
        
        // Shell comments/interface
        $shell1 = "FilesMan" nocase ascii wide
        $shell2 = "WSO" nocase ascii wide 
        $shell3 = "b374k" nocase ascii wide
        $shell4 = "AnonymousFox" nocase ascii wide
        $shell5 = "r57shell" nocase ascii wide
        $shell6 = "c99shell" nocase ascii wide
        
        // File operations
        $file1 = "file_get_contents(" nocase ascii wide
        $file2 = "file_put_contents(" nocase ascii wide
        $file3 = "fwrite(" nocase ascii wide
        $file4 = "readfile(" nocase ascii wide
        
        // Upload functions
        $upload1 = "move_uploaded_file(" nocase ascii wide
        $upload2 = "is_uploaded_file(" nocase ascii wide
        
    condition:
        // Look for PHP file
        (uint32(0) == 0x68703F3C or uint32(0) == 0x3C3F7068) and 
        (
            // Execution function with input
            (1 of ($func_exec*) and 1 of ($input*)) or
            // Obfuscation with input or execution
            (1 of ($obf*) and (1 of ($input*) or 1 of ($func_exec*))) or
            // Known webshell signature
            1 of ($shell*) or
            // File ops with execution
            (1 of ($file*) and 1 of ($func_exec*)) or
            // Upload with execution
            (1 of ($upload*) and 1 of ($func_exec*)) or
            // Multiple suspicious indicators
            (2 of ($func_exec*) and 1 of ($obf*))
        )
}