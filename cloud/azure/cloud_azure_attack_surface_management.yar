/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Attack Surface Management
   Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path
*/

rule cloud_azure_attack_surface_management {
    meta:
        description = "Detects suspicious configurations, attack surface expansion, and attack path issues in Azure environments"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path"
        severity = "high"
        
    strings:
        // Attack Surface Management identifiers
        $asm_id1 = "Microsoft.Security/attackPathsAnalysis" ascii wide
        $asm_id2 = "Defender EASM" ascii wide
        $asm_id3 = "Microsoft Defender External Attack Surface Management" ascii wide
        $asm_id4 = "attack path" nocase ascii wide
        $asm_id5 = "attack surface" nocase ascii wide
        $asm_id6 = "external attack surface" nocase ascii wide
        $asm_id7 = "attackPathsAnalyses" ascii wide
        
        // Attack Surface API and tools
        $asm_api1 = "attackPath" ascii wide
        $asm_api2 = "attackPathsAnalysis" ascii wide
        $asm_api3 = "externalAttackSurface" ascii wide
        $asm_api4 = "Get-AzAttackPath" ascii wide
        $asm_api5 = "AttackPathsProperties" ascii wide
        $asm_api6 = "az security attack-path" ascii wide
        $asm_api7 = "Get-AzSecurityAttackPath" ascii wide
        
        // Resource exposure indicators
        $exposure1 = "public endpoint" nocase ascii wide
        $exposure2 = "exposed resource" nocase ascii wide
        $exposure3 = "internet exposed" nocase ascii wide
        $exposure4 = "internet facing" nocase ascii wide
        $exposure5 = "publicly accessible" nocase ascii wide
        $exposure6 = "external IP" nocase ascii wide
        $exposure7 = "publicIPAddress" ascii wide
        $exposure8 = "endpoint exposed" nocase ascii wide
        
        // Shadow IT and asset discovery
        $shadow1 = "unmanaged resource" nocase ascii wide
        $shadow2 = "shadow it" nocase ascii wide
        $shadow3 = "unknown asset" nocase ascii wide
        $shadow4 = "discovery" nocase ascii wide
        $shadow5 = "asset inventory" nocase ascii wide
        $shadow6 = "resource discovery" nocase ascii wide
        $shadow7 = "unmanaged subscription" nocase ascii wide
        $shadow8 = "AssetDiscovery" ascii wide
        
        // Attack path analysis
        $path1 = "attackPath" ascii wide
        $path2 = "attack path" nocase ascii wide
        $path3 = "critical path" nocase ascii wide
        $path4 = "choke point" nocase ascii wide
        $path5 = "lateral movement" nocase ascii wide
        $path6 = "lateral movement path" nocase ascii wide
        $path7 = "privilege escalation path" nocase ascii wide
        $path8 = "attack chain" nocase ascii wide
        
        // Vulnerability management and assessment
        $vuln1 = "vulnerability assessment" nocase ascii wide
        $vuln2 = "vulnerability" nocase ascii wide
        $vuln3 = "exposure score" nocase ascii wide
        $vuln4 = "Microsoft Defender Vulnerability Management" nocase ascii wide
        $vuln5 = "CVE" ascii wide
        $vuln6 = "CWE" ascii wide
        $vuln7 = "CVSS" ascii wide
        $vuln8 = "remediationSteps" ascii wide
        
        // Suspicious configuration changes expanding attack surface
        $config1 = "network security group" nocase ascii wide
        $config2 = "firewall rule" nocase ascii wide
        $config3 = "public access" nocase ascii wide
        $config4 = "security rule" nocase ascii wide
        $config5 = "destination port range" nocase ascii wide
        $config6 = "source address prefix" nocase ascii wide
        $config7 = "allow inbound" nocase ascii wide
        $config8 = "* Any Any Allow" nocase ascii wide
        
        // Risky changes expanding attack surface
        $risky1 = "change public access" nocase ascii wide
        $risky2 = "add public IP" nocase ascii wide
        $risky3 = "create public endpoint" nocase ascii wide
        $risky4 = "expose port" nocase ascii wide
        $risky5 = "open port" nocase ascii wide
        $risky6 = "expose to internet" nocase ascii wide
        $risky7 = "add inbound rule" nocase ascii wide
        $risky8 = "expand access" nocase ascii wide
        
        // Suspicious values that increase attack surface
        $susp_value1 = "0.0.0.0/0" ascii wide
        $susp_value2 = "* Any Any Allow" ascii wide
        $susp_value3 = "Internet" ascii wide
        $susp_value4 = "Any" ascii wide
        $susp_value5 = "Port: *" ascii wide
        $susp_value6 = "\"direction\": \"Inbound\"" ascii wide
        $susp_value7 = "\"access\": \"Allow\"" ascii wide
        $susp_value8 = "Priority 100" ascii wide
        
        // Common attack paths
        $common_path1 = "keyVault to subscription" nocase ascii wide
        $common_path2 = "identity to keyvault" nocase ascii wide
        $common_path3 = "publicIP to virtualMachine" nocase ascii wide
        $common_path4 = "managedIdentity to" nocase ascii wide
        $common_path5 = "servicePrincipal to" nocase ascii wide
        $common_path6 = "managementPort to" nocase ascii wide
        $common_path7 = "storageAccount to" nocase ascii wide
        $common_path8 = "webApplication to" nocase ascii wide
        
    condition:
        // Confirm it's related to Attack Surface Management
        (any of ($asm_id*) or any of ($asm_api*) or any of ($path*)) and
        
        (
            // Resource exposure issues
            (1 of ($exposure*) and 1 of ($susp_value*)) or
            
            // Shadow IT issues
            (1 of ($shadow*)) or
            
            // Direct attack path identification
            (1 of ($path*) and 1 of ($common_path*)) or
            
            // Vulnerability management issues
            (1 of ($vuln*) and 1 of ($exposure*)) or
            
            // Suspicious configuration expanding attack surface
            (1 of ($config*) and 1 of ($susp_value*)) or
            
            // Risky changes
            (1 of ($risky*)) or
            
            // Multiple suspicious indicators
            (2 of ($susp_value*)) or
            
            // Combination of attack surface patterns
            ((1 of ($exposure*) and 1 of ($risky*)) or
             (1 of ($config*) and 1 of ($risky*)) or
             (1 of ($path*) and 1 of ($exposure*)))
        )
}