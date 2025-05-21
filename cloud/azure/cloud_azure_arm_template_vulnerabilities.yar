/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure ARM Template Vulnerabilities
   Reference: https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/best-practices
*/

rule cloud_azure_arm_template_vulnerabilities {
    meta:
        description = "Detects potential security issues in Azure ARM templates"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/best-practices"
        severity = "medium"
        
    strings:
        // Template file indicators
        $template_header = "\"$schema\": \"https://schema.management.azure.com/schemas" ascii wide
        $template_header2 = "\"contentVersion\":" ascii wide
        $template_header3 = "\"resources\": [" ascii wide
        
        // Vulnerable IAM configurations
        $iam_vuln1 = "\"roleDefinitionId\": \"[concat" ascii wide
        $iam_vuln2 = "\"role\": \"Owner\"" nocase ascii wide
        $iam_vuln3 = "\"actions\": [\"*\"]" ascii wide
        $iam_vuln4 = "\"notActions\": []" ascii wide
        $iam_vuln5 = "\"principalType\": \"ServicePrincipal\"" ascii wide
        
        // Storage account vulnerabilities
        $storage_vuln1 = "\"networkAcls\": {" ascii wide
        $storage_vuln2 = "\"defaultAction\": \"Allow\"" ascii wide
        $storage_vuln3 = "\"publicNetworkAccess\": \"Enabled\"" ascii wide
        $storage_vuln4 = "\"allowBlobPublicAccess\": true" ascii wide
        $storage_vuln5 = "\"supportsHttpsTrafficOnly\": false" ascii wide
        
        // Key Vault vulnerabilities
        $keyvault_vuln1 = "\"enableRbacAuthorization\": false" ascii wide
        $keyvault_vuln2 = "\"enableSoftDelete\": false" ascii wide
        $keyvault_vuln3 = "\"enablePurgeProtection\": false" ascii wide
        
        // Network security group vulnerabilities
        $nsg_vuln1 = "\"destinationPortRange\": \"*\"" ascii wide
        $nsg_vuln2 = "\"sourceAddressPrefix\": \"*\"" ascii wide
        $nsg_vuln3 = "\"access\": \"Allow\"" ascii wide
        $nsg_vuln4 = "\"direction\": \"Inbound\"" ascii wide
        $nsg_vuln5 = "\"protocol\": \"*\"" ascii wide
        
        // SQL/Database vulnerabilities
        $sql_vuln1 = "\"startIpAddress\": \"0.0.0.0\"" ascii wide
        $sql_vuln2 = "\"endIpAddress\": \"255.255.255.255\"" ascii wide
        $sql_vuln3 = "\"minimalTlsVersion\": \"None\"" ascii wide
        $sql_vuln4 = "\"publicNetworkAccess\": \"Enabled\"" ascii wide
        
        // Hardcoded secrets and credentials
        $secret1 = "\"adminPassword\":" ascii wide
        $secret2 = "\"password\":" ascii wide
        $secret3 = "\"accessKey\":" ascii wide
        $secret4 = "\"connectionString\":" ascii wide
        $secret5 = "\"primaryKey\":" ascii wide
        
        // Diagnostic settings disabled
        $diag_vuln1 = "\"diagnosticSettings\": {" ascii wide
        $diag_vuln2 = "\"enabled\": false" ascii wide
        
    condition:
        // Confirm it's an ARM template
        ($template_header or $template_header2) and $template_header3 and
        
        (
            // IAM vulnerabilities
            (2 of ($iam_vuln*)) or
            
            // Storage account vulnerabilities with overly permissive networking
            ($storage_vuln1 and 1 of ($storage_vuln2, $storage_vuln3, $storage_vuln4, $storage_vuln5)) or
            
            // Key Vault vulnerabilities
            (1 of ($keyvault_vuln*)) or
            
            // Overly permissive NSG rule (if all these exist together, it's a serious security issue)
            ($nsg_vuln1 and $nsg_vuln2 and $nsg_vuln3 and $nsg_vuln4 and $nsg_vuln5) or
            
            // SQL Server with public access from anywhere
            ($sql_vuln1 and $sql_vuln2) or
            
            // Hardcoded credentials in templates (multiple instances make it more suspicious)
            (2 of ($secret*)) or
            
            // Diagnostic settings disabled
            ($diag_vuln1 and $diag_vuln2)
        )
}