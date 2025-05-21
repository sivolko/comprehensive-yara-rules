/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Credentials
   Reference: https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-portal
*/

rule cloud_azure_credentials_leaked {
    meta:
        description = "Detects Azure credentials and secrets in files"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-portal"
        severity = "critical"
        
    strings:
        // Azure AD Application/Client IDs - GUID format
        $client_id1 = /client[_-]id["']\s*[:=]\s*["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']/ nocase ascii wide
        $client_id2 = /app[_-]id["']\s*[:=]\s*["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']/ nocase ascii wide
        
        // Azure Tenant IDs
        $tenant_id = /tenant[_-]id["']\s*[:=]\s*["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']/ nocase ascii wide
        
        // Azure Client Secrets
        $client_secret1 = /client[_-]secret["']\s*[:=]\s*["'][^\n"']{10,}["']/ nocase ascii wide
        $client_secret2 = /secret["']\s*[:=]\s*["'][^\n"']{10,}["']/ nocase ascii wide
        
        // Azure Storage Account keys
        $storage_key = /[Ss]torage[Aa]ccount[Kk]ey["']\s*[:=]\s*["'][A-Za-z0-9+\/=]{88}["']/ nocase ascii wide
        
        // Azure SAS tokens
        $sas_token1 = /sig=[a-zA-Z0-9%]+/ nocase ascii wide
        $sas_token2 = /sv=[0-9]{4}-[0-9]{2}-[0-9]{2}/ nocase ascii wide
        
        // Azure connection strings
        $connection_string1 = /DefaultEndpointsProtocol=https;AccountName=/ nocase ascii wide
        $connection_string2 = /AccountKey=[A-Za-z0-9+\/=]+/ nocase ascii wide
        
        // Azure Key Vault references
        $keyvault1 = /https:\/\/[a-zA-Z0-9\-]+\.vault\.azure\.net/ nocase ascii wide
        $keyvault2 = /keyvault:\/\/[a-zA-Z0-9\-]+\.vault\.azure\.net/ nocase ascii wide
        
        // Azure configuration contexts
        $azure_context1 = "AzureWebJobsStorage" nocase ascii wide
        $azure_context2 = "AZURE_STORAGE_CONNECTION_STRING" nocase ascii wide
        $azure_context3 = "AZURE_CLIENT_SECRET" nocase ascii wide
        $azure_context4 = "AzureAD" nocase ascii wide
        $azure_context5 = "az login" ascii wide
        
    condition:
        // Combination of client IDs with secrets
        (($client_id1 or $client_id2) and ($client_secret1 or $client_secret2)) or
        
        // Azure storage account credentials
        (any of ($connection_string*)) or
        
        // SAS token indicators
        ($sas_token1 and $sas_token2) or
        
        // Key Vault with context
        (any of ($keyvault*) and any of ($azure_context*)) or
        
        // Very specific indicator
        $storage_key
}