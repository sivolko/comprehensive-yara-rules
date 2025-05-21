/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Identity Attacks
   Reference: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema
*/

rule cloud_azure_identity_attacks {
    meta:
        description = "Detects potential Azure identity-based attacks and privilege escalation"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema"
        severity = "critical"
        
    strings:
        // Azure AD identity identifiers
        $aad_id1 = "Microsoft.AAD" ascii wide
        $aad_id2 = "Microsoft.Entra" ascii wide
        $aad_id3 = "Microsoft.Azure.ActiveDirectory" ascii wide
        $aad_id4 = "Microsoft.Identity" ascii wide
        $aad_id5 = "Microsoft.Graph" ascii wide
        $aad_id6 = "MicrosoftGraphAPI" ascii wide
        $aad_id7 = "Microsoft.Authorization" ascii wide
        
        // AzureAD PowerShell/CLI tools
        $aad_tools1 = "AzureAD" ascii wide
        $aad_tools2 = "az ad" ascii wide
        $aad_tools3 = "Connect-AzureAD" ascii wide
        $aad_tools4 = "Connect-MgGraph" ascii wide
        $aad_tools5 = "Microsoft.Graph.Authentication" ascii wide
        $aad_tools6 = "Connect-MsolService" ascii wide
        $aad_tools7 = "New-AzureADServicePrincipal" ascii wide
        
        // Suspicious admin operations - user creation/modification
        $admin_op1 = "New-AzureADUser" ascii wide
        $admin_op2 = "New-MsolUser" ascii wide
        $admin_op3 = "Add-AzureADDirectoryRole" ascii wide
        $admin_op4 = "New-AzureRmRoleAssignment" ascii wide
        $admin_op5 = "Add-MsolRoleMember" ascii wide
        $admin_op6 = "Set-AzureADUser" ascii wide
        $admin_op7 = "Update-MsolUser" ascii wide
        $admin_op8 = "Set-MsolUserPassword" ascii wide
        $admin_op9 = "Reset-MsolUserPassword" ascii wide
        
        // High privilege role operations
        $privs1 = "Company Administrator" ascii wide
        $privs2 = "Global Administrator" ascii wide
        $privs3 = "Privileged Role Administrator" ascii wide
        $privs4 = "User Account Administrator" ascii wide
        $privs5 = "Authentication Administrator" ascii wide
        $privs6 = "Security Administrator" ascii wide
        $privs7 = "Application Administrator" ascii wide
        $privs8 = "Owner" ascii wide
        $privs9 = "Contributor" ascii wide
        
        // Service principal/app operations (potential backdoors)
        $sp_ops1 = "New-AzureADServicePrincipal" ascii wide
        $sp_ops2 = "New-AzureADApplication" ascii wide
        $sp_ops3 = "Add-AzureADServicePrincipalOwner" ascii wide
        $sp_ops4 = "New-AzADServicePrincipal" ascii wide
        $sp_ops5 = "New-AzADAppCredential" ascii wide
        $sp_ops6 = "New-AzureADApplicationPasswordCredential" ascii wide
        $sp_ops7 = "AddKey" ascii wide
        $sp_ops8 = "addPassword" ascii wide
        
        // Credential harvesting
        $cred1 = "Export-AzADApplication" ascii wide
        $cred2 = "Get-AzureADApplicationPasswordCredential" ascii wide
        $cred3 = "Get-MsolServicePrincipalCredential" ascii wide
        $cred4 = "Export-PfxCertificate" ascii wide
        $cred5 = "Export-AzKeyVaultSecret" ascii wide
        
        // Suspicious methods/patterns
        $susp1 = "ApplicationId" ascii wide
        $susp2 = "redirectUri" ascii wide
        $susp3 = "validatedDomain" ascii wide
        $susp4 = "tokenSigningCertificate" ascii wide
        $susp5 = "ConsentType.AllPrincipals" ascii wide
        $susp6 = ".withAllowedClient" ascii wide
        $susp7 = "User.ReadWrite.All" ascii wide
        $susp8 = "Directory.ReadWrite.All" ascii wide
        $susp9 = "RoleManagement.ReadWrite.Directory" ascii wide
        
        // Attack tools/frameworks
        $tool1 = "AzureHound" nocase ascii wide
        $tool2 = "MicroBurst" nocase ascii wide
        $tool3 = "PowerZure" nocase ascii wide
        $tool4 = "AADInternals" nocase ascii wide
        $tool5 = "ROADtools" nocase ascii wide
        $tool6 = "Microsoft Graph Explorer" nocase ascii wide
        
    condition:
        // Identify Azure AD context
        (any of ($aad_id*) or any of ($aad_tools*)) and
        
        (
            // Suspicious admin operations combined with high privilege roles
            (1 of ($admin_op*) and 1 of ($privs*)) or
            
            // Service principal operations (potential backdoor creation)
            (1 of ($sp_ops*) and 1 of ($privs*)) or
            
            // Credential extraction or harvesting
            (1 of ($cred*)) or
            
            // Admin tool with highly suspicious methods
            (1 of ($aad_tools*) and 1 of ($susp*)) or
            
            // Multiple suspicious permissions or operations
            (2 of ($susp*)) or
            
            // Known attack tools
            (any of ($tool*)) or
            
            // Multiple admin operations indicate possible account takeover
            (2 of ($admin_op*))
        )
}