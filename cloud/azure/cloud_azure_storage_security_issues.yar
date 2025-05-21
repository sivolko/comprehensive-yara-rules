/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Storage Security
   Reference: https://learn.microsoft.com/en-us/azure/storage/common/storage-security-guide
*/

rule cloud_azure_storage_security_issues {
    meta:
        description = "Detects Azure Storage misconfigurations and potential attacks"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/storage/common/storage-security-guide"
        severity = "high"
        
    strings:
        // Azure Storage identification strings
        $storage_id1 = "Microsoft.Storage" ascii wide
        $storage_id2 = "StorageAccount" ascii wide
        $storage_id3 = ".blob.core.windows.net" ascii wide
        $storage_id4 = ".file.core.windows.net" ascii wide
        $storage_id5 = ".table.core.windows.net" ascii wide
        $storage_id6 = ".queue.core.windows.net" ascii wide
        $storage_id7 = "azure-storage-" ascii wide
        $storage_id8 = "AzureStorageAccount" ascii wide
        
        // Azure Storage SDK
        $storage_sdk1 = "Azure.Storage.Blobs" ascii wide
        $storage_sdk2 = "Azure.Storage.Files" ascii wide
        $storage_sdk3 = "Azure.Storage.Queues" ascii wide
        $storage_sdk4 = "Azure.Storage.Tables" ascii wide
        $storage_sdk5 = "WindowsAzure.Storage" ascii wide
        $storage_sdk6 = "microsoft-azure-storage" ascii wide
        $storage_sdk7 = "@azure/storage-" ascii wide
        
        // CLI/PowerShell tools
        $storage_tool1 = "az storage" ascii wide
        $storage_tool2 = "New-AzStorageAccount" ascii wide
        $storage_tool3 = "Set-AzStorageAccount" ascii wide
        $storage_tool4 = "Get-AzStorageAccountKey" ascii wide
        $storage_tool5 = "Get-AzureStorageKey" ascii wide
        $storage_tool6 = "AzureStorageExplorer" ascii wide
        
        // Security misconfigurations
        $misconfig1 = "AllowBlobPublicAccess" ascii wide
        $misconfig2 = "PublicNetworkAccess" ascii wide
        $misconfig3 = "NetworkAcls" ascii wide
        $misconfig4 = "bypass" ascii wide
        $misconfig5 = "AllowSharedKeyAccess" ascii wide
        $misconfig6 = "DefaultAction" ascii wide
        $misconfig7 = "allowPublicAccess" ascii wide
        $misconfig8 = "legacyAuthenticationEnabled" ascii wide
        
        // Values indicating misconfiguration
        $bad_value1 = "AllowBlobPublicAccess = true" nocase ascii wide
        $bad_value2 = "PublicNetworkAccess = Enabled" nocase ascii wide
        $bad_value3 = "bypass = AzureServices" nocase ascii wide
        $bad_value4 = "DefaultAction = Allow" nocase ascii wide
        $bad_value5 = "allowPublicAccess = true" nocase ascii wide
        $bad_value6 = "supportsHttpsTrafficOnly = false" nocase ascii wide
        $bad_value7 = "enableHttpsTrafficOnly = false" nocase ascii wide
        $bad_value8 = "publicAccess = \"Blob\"" nocase ascii wide
        $bad_value9 = "publicAccess = \"Container\"" nocase ascii wide
        
        // SAS token related
        $sas1 = "SharedAccessSignature" ascii wide
        $sas2 = "sig=" ascii wide
        $sas3 = "se=" ascii wide
        $sas4 = "sp=" ascii wide
        $sas5 = "sv=" ascii wide
        $sas6 = "srt=" ascii wide
        $sas7 = "generateAccountSasQueryParameters" ascii wide
        $sas8 = "generateBlobSasQueryParameters" ascii wide
        
        // Storage account attack and enumeration
        $attack1 = "List all containers" nocase ascii wide
        $attack2 = "brute force" nocase ascii wide
        $attack3 = "scan storage account" nocase ascii wide
        $attack4 = "enumerate blob" nocase ascii wide
        $attack5 = "find public" nocase ascii wide
        $attack6 = "--include-deleted" ascii wide
        $attack7 = "recover" ascii wide
        $attack8 = "--auth-mode login" ascii wide
        
        // Data exfiltration
        $exfil1 = "Upload blob" ascii wide
        $exfil2 = "az storage blob upload" ascii wide
        $exfil3 = "Set-AzStorageBlobContent" ascii wide
        $exfil4 = "uploadFile" ascii wide
        $exfil5 = "uploadFromFile" ascii wide
        $exfil6 = "uploadStream" ascii wide
        $exfil7 = "downloadFile" ascii wide
        $exfil8 = "downloadToFile" ascii wide
        
    condition:
        // Confirm it's about Azure Storage
        (any of ($storage_id*) or any of ($storage_sdk*) or any of ($storage_tool*)) and
        
        (
            // Check for misconfigurations (Security risk)
            (1 of ($misconfig*) and 1 of ($bad_value*)) or
            
            // Overly permissive SAS tokens with suspicious activity
            (2 of ($sas*) and 1 of ($attack*)) or
            
            // Direct attack patterns
            (2 of ($attack*)) or
            
            // Data exfiltration with insecure context
            (1 of ($exfil*) and (1 of ($bad_value*) or 1 of ($attack*))) or
            
            // Multiple security misconfigurations (high risk)
            (3 of ($bad_value*))
        )
}