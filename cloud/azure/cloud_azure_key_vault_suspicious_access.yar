/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Key Vault Security
   Reference: https://learn.microsoft.com/en-us/azure/key-vault/general/security-features
*/

rule cloud_azure_key_vault_suspicious_access {
    meta:
        description = "Detects suspicious access patterns to Azure Key Vault"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features"
        severity = "high"
        
    strings:
        // Key Vault identification strings
        $keyvault_uri1 = ".vault.azure.net" nocase ascii wide
        $keyvault_uri2 = "https://[a-zA-Z0-9\\-]+\\.vault\\.azure\\.net" nocase ascii wide
        
        // Resource identifiers and API calls
        $kv_api1 = "/secrets/" ascii wide
        $kv_api2 = "/keys/" ascii wide
        $kv_api3 = "/certificates/" ascii wide
        $kv_api4 = "/deletedvaults/" ascii wide
        $kv_api5 = "/providers/Microsoft.KeyVault/" ascii wide
        
        // SDK library usage
        $kv_sdk1 = "Microsoft.Azure.KeyVault" ascii wide
        $kv_sdk2 = "Azure.Security.KeyVault" ascii wide
        $kv_sdk3 = "@azure/keyvault-" ascii wide
        $kv_sdk4 = "azure-keyvault" ascii wide
        
        // Key Vault operations (high risk)
        $kv_op_high1 = "GetDeletedVault" ascii wide
        $kv_op_high2 = "PurgeDeletedVault" ascii wide
        $kv_op_high3 = "RecoverDeletedVault" ascii wide
        $kv_op_high4 = "DeleteVault" ascii wide
        $kv_op_high5 = "UpdateKeyVaultNetworkRuleSet" ascii wide
        $kv_op_high6 = "getPurgeProtection" ascii wide
        $kv_op_high7 = "DisableKeyProtection" ascii wide
        
        // Key Vault operations (medium risk)
        $kv_op_med1 = "UpdateAccessPolicy" ascii wide
        $kv_op_med2 = "setAccessPolicy" ascii wide
        $kv_op_med3 = "deleteAccessPolicy" ascii wide
        $kv_op_med4 = "setNetworkAcls" ascii wide
        $kv_op_med5 = "getNetworkAcls" ascii wide
        $kv_op_med6 = "DiagnosticSettings" ascii wide
        
        // Key and secret operations (high risk)
        $kv_secret_op1 = "BackupSecret" ascii wide
        $kv_secret_op2 = "DeleteSecret" ascii wide
        $kv_secret_op3 = "PurgeDeletedSecret" ascii wide
        $kv_secret_op4 = "RestoreSecret" ascii wide
        $kv_secret_op5 = "DeleteKey" ascii wide
        $kv_secret_op6 = "BackupKey" ascii wide
        
        // Command line and script patterns
        $cli1 = "az keyvault" ascii wide
        $cli2 = "Remove-AzKeyVault" ascii wide
        $cli3 = "New-AzKeyVault" ascii wide
        $cli4 = "Set-AzKeyVaultAccessPolicy" ascii wide
        $cli5 = "Remove-AzKeyVaultAccessPolicy" ascii wide
        $cli6 = "az keyvault secret" ascii wide
        
        // Suspicious access patterns
        $susp1 = "firewall bypass" nocase ascii wide
        $susp2 = "export all secrets" nocase ascii wide
        $susp3 = "download all keys" nocase ascii wide
        $susp4 = "export-keyvault" nocase ascii wide
        $susp5 = "for-json" nocase ascii wide
        $susp6 = "foreach" nocase ascii wide
        
        // JavaScript or PowerShell loop patterns to bulk access secrets
        $loop1 = "forEach" ascii wide
        $loop2 = "for(" ascii wide
        $loop3 = "for (" ascii wide
        $loop4 = "foreach (" ascii wide
        $loop5 = "ForEach-Object" ascii wide
        
    condition:
        // At least one Key Vault identifier is present
        (any of ($keyvault_uri*) or any of ($kv_api*) or any of ($kv_sdk*)) and
        
        (
            // High risk Key Vault operations
            (1 of ($kv_op_high*)) or
            
            // Medium risk operations combined with suspicious patterns
            (1 of ($kv_op_med*) and 1 of ($susp*)) or
            
            // Secret/key operations within loops (potential bulk access/exfiltration)
            (1 of ($kv_secret_op*) and 1 of ($loop*)) or
            
            // CLI commands with suspicious patterns
            (1 of ($cli*) and 1 of ($susp*)) or
            
            // Multiple high-risk CLI operations
            (2 of ($cli*)) or
            
            // Bulk secret operations
            (2 of ($kv_secret_op*))
        )
}