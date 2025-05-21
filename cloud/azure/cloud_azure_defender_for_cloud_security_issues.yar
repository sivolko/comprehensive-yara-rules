/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Microsoft Defender for Cloud Security
   Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
*/

rule cloud_azure_defender_for_cloud_security_issues {
    meta:
        description = "Detects tampering, disabling, or bypassing of Microsoft Defender for Cloud"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"
        severity = "critical"
        
    strings:
        // Defender for Cloud identifiers
        $defender_id1 = "Microsoft.Security" ascii wide
        $defender_id2 = "Security Center" ascii wide
        $defender_id3 = "Defender for Cloud" ascii wide
        $defender_id4 = "Azure Security Center" ascii wide
        $defender_id5 = "Azure Defender" ascii wide
        $defender_id6 = "securityCenter" ascii wide
        $defender_id7 = "ASC" ascii wide
        $defender_id8 = "Microsoft Defender for" ascii wide
        
        // Defender API/SDK identifiers
        $defender_sdk1 = "Microsoft.Azure.Management.Security" ascii wide
        $defender_sdk2 = "Azure.ResourceManager.Security" ascii wide
        $defender_sdk3 = "Microsoft.Azure.Commands.Security" ascii wide
        $defender_sdk4 = "@azure/arm-security" ascii wide
        $defender_sdk5 = "SecurityCenter" ascii wide
        $defender_sdk6 = "Az.Security" ascii wide
        
        // Defender CLI/PowerShell commands
        $defender_cmd1 = "az security" ascii wide
        $defender_cmd2 = "Get-AzSecurityAlert" ascii wide
        $defender_cmd3 = "Get-AzSecurityPricing" ascii wide
        $defender_cmd4 = "Set-AzSecurityPricing" ascii wide
        $defender_cmd5 = "Get-AzSecuritySetting" ascii wide
        $defender_cmd6 = "Set-AzSecuritySetting" ascii wide
        $defender_cmd7 = "Get-AzSecurityTask" ascii wide
        $defender_cmd8 = "Update-AzSecurityAlert" ascii wide
        
        // Pricing and plan-related strings
        $pricing1 = "pricings" ascii wide
        $pricing2 = "standard tier" nocase ascii wide
        $pricing3 = "pricing tier" nocase ascii wide
        $pricing4 = "free tier" nocase ascii wide
        $pricing5 = "pricingTier" ascii wide
        $pricing6 = "tier = \"Free\"" ascii wide
        $pricing7 = "subPlan" ascii wide
        $pricing8 = "pricing = standard" nocase ascii wide
        
        // Tampering with Defender components
        $tamper1 = "\"pricingTier\": \"Free\"" ascii wide
        $tamper2 = "\"pricingTier\": \"Standard\"" ascii wide
        $tamper3 = "Enable = false" nocase ascii wide
        $tamper4 = "isEnabled = false" nocase ascii wide
        $tamper5 = "disable defender" nocase ascii wide
        $tamper6 = "disable security center" nocase ascii wide
        $tamper7 = "disable monitoring" nocase ascii wide
        $tamper8 = "turn off defender" nocase ascii wide
        
        // Changing security settings
        $settings1 = "autoProvision = \"Off\"" nocase ascii wide
        $settings2 = "\"autoProvision\": \"Off\"" ascii wide
        $settings3 = "autoProvision" ascii wide
        $settings4 = "SecurityContact" ascii wide
        $settings5 = "securityContacts" ascii wide
        $settings6 = "workspaceSettings" ascii wide
        $settings7 = "securitySettings" ascii wide
        $settings8 = "\"alertNotifications\": \"Off\"" ascii wide
        
        // Defender cloud components/plans
        $component1 = "ContainerRegistry" ascii wide
        $component2 = "KubernetesService" ascii wide
        $component3 = "VirtualMachines" ascii wide
        $component4 = "SqlServers" ascii wide
        $component5 = "AppServices" ascii wide
        $component6 = "StorageAccounts" ascii wide
        $component7 = "SqlServerVirtualMachines" ascii wide
        $component8 = "KeyVaults" ascii wide
        $component9 = "Dns" ascii wide
        $component10 = "Arm" ascii wide
        
        // Suspicious Defender operations
        $susp_op1 = "dismiss alert" nocase ascii wide
        $susp_op2 = "dismiss recommendation" nocase ascii wide
        $susp_op3 = "exempt" nocase ascii wide
        $susp_op4 = "disable security" nocase ascii wide
        $susp_op5 = "disable email notification" nocase ascii wide
        $susp_op6 = "set-azsecurityautoprovision" ascii wide
        $susp_op7 = "turn off security" nocase ascii wide
        $susp_op8 = "azureSecurityAgents" ascii wide
        
        // Defender agent manipulation
        $agent1 = "uninstall agent" nocase ascii wide
        $agent2 = "uninstall monitoring agent" nocase ascii wide
        $agent3 = "monitoring agent" nocase ascii wide
        $agent4 = "MMAExtension" ascii wide
        $agent5 = "AzureSecurityLinuxAgent" ascii wide
        $agent6 = "AzureSecurityWindowsAgent" ascii wide
        $agent7 = "stopservice" nocase ascii wide
        $agent8 = "LogAnalytics agent" nocase ascii wide
        
        // Disabling specific protections
        $protection1 = "jitNetworkAccessPolicies" ascii wide
        $protection2 = "adaptive network hardening" nocase ascii wide
        $protection3 = "adaptive application control" nocase ascii wide
        $protection4 = "just in time" nocase ascii wide
        $protection5 = "file integrity monitoring" nocase ascii wide
        $protection6 = "regulatory compliance" nocase ascii wide
        $protection7 = "disable vulnerability assessment" nocase ascii wide
        $protection8 = "disable scanning" nocase ascii wide
        
    condition:
        // Confirm it's related to Defender for Cloud
        (any of ($defender_id*) or any of ($defender_sdk*) or any of ($defender_cmd*)) and
        
        (
            // Changing pricing tier from Standard to Free (disabling protection)
            (1 of ($pricing*) and 1 of ($tamper*)) or
            
            // Disabling automatic provisioning of monitoring agents
            (1 of ($settings*) and 1 of ($tamper*)) or
            
            // Specific component being disabled
            (1 of ($component*) and 1 of ($tamper*)) or
            
            // Suspicious operations against Defender
            (any of ($susp_op*)) or
            
            // Agent manipulation
            (any of ($agent*)) or
            
            // Disabling specific protections
            (1 of ($protection*) and 1 of ($tamper*)) or
            
            // Multiple tampering signals
            (2 of ($tamper*)) or
            
            // Multiple component changes
            (2 of ($component*) and 1 of ($tamper*))
        )
}