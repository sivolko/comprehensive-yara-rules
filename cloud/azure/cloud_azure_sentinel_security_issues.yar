/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Microsoft Sentinel Security
   Reference: https://learn.microsoft.com/en-us/azure/sentinel/overview
*/

rule cloud_azure_sentinel_security_issues {
    meta:
        description = "Detects potential security issues, tampering or bypassing of Microsoft Sentinel"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/sentinel/overview"
        severity = "critical"
        
    strings:
        // Sentinel identifiers
        $sentinel_id1 = "Microsoft.SecurityInsights" ascii wide
        $sentinel_id2 = "Microsoft.OperationalInsights" ascii wide
        $sentinel_id3 = "SecurityInsights" ascii wide
        $sentinel_id4 = "Microsoft Sentinel" ascii wide
        $sentinel_id5 = "Azure Sentinel" ascii wide
        $sentinel_id6 = "API: Microsoft.SecurityInsights" ascii wide
        $sentinel_id7 = "sentinel/" ascii wide
        
        // Sentinel API/SDK
        $sentinel_sdk1 = "SecurityInsights/operations" ascii wide
        $sentinel_sdk2 = "sentinel/alert" ascii wide
        $sentinel_sdk3 = "sentinel/incident" ascii wide
        $sentinel_sdk4 = "sentinel/alertRule" ascii wide
        $sentinel_sdk5 = "sentinel/dataConnector" ascii wide
        $sentinel_sdk6 = "sentinel/hunting" ascii wide
        $sentinel_sdk7 = "Az.SecurityInsights" ascii wide
        $sentinel_sdk8 = "Microsoft.Azure.Management.SecurityInsights" ascii wide
        
        // Sentinel CLI/PowerShell commands
        $sentinel_cmd1 = "Az.SecurityInsights" ascii wide
        $sentinel_cmd2 = "Get-AzSentinel" ascii wide
        $sentinel_cmd3 = "New-AzSentinel" ascii wide
        $sentinel_cmd4 = "Remove-AzSentinel" ascii wide
        $sentinel_cmd5 = "Update-AzSentinel" ascii wide
        $sentinel_cmd6 = "az sentinel" ascii wide
        $sentinel_cmd7 = "az security insight" ascii wide
        
        // Log Analytics workspace related
        $workspace1 = "Microsoft.OperationalInsights/workspaces" ascii wide
        $workspace2 = "LogAnalytics" ascii wide
        $workspace3 = "OperationalInsights" ascii wide
        $workspace4 = "workspace/" ascii wide
        $workspace5 = "immediatePurgeDataOn" ascii wide
        
        // Sentinel rule tampering/modification
        $rule_mod1 = "alertRules" ascii wide
        $rule_mod2 = "analyticsRules" ascii wide
        $rule_mod3 = "scheduled" ascii wide
        $rule_mod4 = "fusion" ascii wide
        $rule_mod5 = "mlBehaviorAnalytics" ascii wide
        $rule_mod6 = "enabled = false" nocase ascii wide
        $rule_mod7 = "disabled" nocase ascii wide
        $rule_mod8 = "delete rule" nocase ascii wide
        
        // Data connector tampering
        $connector_mod1 = "dataConnectors" ascii wide
        $connector_mod2 = "connectorId" ascii wide
        $connector_mod3 = "Office365" ascii wide
        $connector_mod4 = "ThreatIntelligence" ascii wide
        $connector_mod5 = "AzureActiveDirectory" ascii wide
        $connector_mod6 = "AzureActivity" ascii wide
        $connector_mod7 = "MicrosoftDefenderAdvancedThreatProtection" ascii wide
        $connector_mod8 = "state = \"Disabled\"" ascii wide
        
        // Incident/Alert tampering
        $incident_mod1 = "incidents" ascii wide
        $incident_mod2 = "alerts" ascii wide
        $incident_mod3 = "close incident" nocase ascii wide
        $incident_mod4 = "close alert" nocase ascii wide
        $incident_mod5 = "status = \"Closed\"" ascii wide
        $incident_mod6 = "classification = \"BenignPositive\"" ascii wide
        $incident_mod7 = "classification = \"FalsePositive\"" ascii wide
        
        // Suspicious operations
        $susp_op1 = "Delete-AzOperationalInsightsWorkspace" ascii wide
        $susp_op2 = "Remove-AzOperationalInsightsWorkspace" ascii wide
        $susp_op3 = "purge" ascii wide
        $susp_op4 = "delete workspace" nocase ascii wide
        $susp_op5 = "remove connector" nocase ascii wide
        $susp_op6 = "disable all rules" nocase ascii wide
        $susp_op7 = "delete all alerts" nocase ascii wide
        $susp_op8 = "sentinel evasion" nocase ascii wide
        
        // SOAR Playbook manipulation
        $playbook1 = "Microsoft.Logic/workflows" ascii wide
        $playbook2 = "playbook" ascii wide
        $playbook3 = "Logic Apps" ascii wide
        $playbook4 = "LogicApp" ascii wide
        $playbook5 = "automation" ascii wide
        $playbook6 = "delete automation" nocase ascii wide
        $playbook7 = "disable playbook" nocase ascii wide
        
    condition:
        // Confirm it's related to Sentinel
        (any of ($sentinel_id*) or any of ($sentinel_sdk*) or any of ($sentinel_cmd*) or any of ($workspace*)) and
        
        (
            // Rule tampering
            (2 of ($rule_mod*)) or
            
            // Data connector disabling
            (2 of ($connector_mod*)) or
            
            // Suspicious incident/alert handling
            (2 of ($incident_mod*)) or
            
            // Direct suspicious operations against Sentinel
            (any of ($susp_op*)) or
            
            // Playbook/automation tampering
            (1 of ($playbook*) and (1 of ($susp_op*) or 1 of ($rule_mod*))) or
            
            // Multiple components being tampered with
            ((1 of ($rule_mod*) and 1 of ($connector_mod*)) or
             (1 of ($rule_mod*) and 1 of ($incident_mod*)) or
             (1 of ($connector_mod*) and 1 of ($incident_mod*)))
        )
}