/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Network Security
   Reference: https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview
*/

rule cloud_azure_network_security_issues {
    meta:
        description = "Detects misconfigurations and suspicious activity in Azure networking components"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview"
        severity = "high"
        
    strings:
        // Azure Network identifiers
        $network_id1 = "Microsoft.Network" ascii wide
        $network_id2 = "virtualNetworks" ascii wide
        $network_id3 = "networkSecurityGroups" ascii wide
        $network_id4 = "applicationGateways" ascii wide
        $network_id5 = "azureFirewalls" ascii wide
        $network_id6 = "virtualNetworkGateways" ascii wide
        $network_id7 = "publicIPAddresses" ascii wide
        $network_id8 = "loadBalancers" ascii wide
        
        // Network CLI/PowerShell tools
        $network_cli1 = "az network" ascii wide
        $network_cli2 = "New-AzVirtualNetwork" ascii wide
        $network_cli3 = "New-AzNetworkSecurityGroup" ascii wide
        $network_cli4 = "New-AzNetworkSecurityRuleConfig" ascii wide
        $network_cli5 = "Set-AzNetworkSecurityRuleConfig" ascii wide
        $network_cli6 = "Add-AzNetworkSecurityRuleConfig" ascii wide
        $network_cli7 = "New-AzPublicIpAddress" ascii wide
        $network_cli8 = "New-AzFirewall" ascii wide
        
        // Network Security Group rule creation/modification
        $nsg_rule1 = "Add-AzNetworkSecurityRuleConfig" ascii wide
        $nsg_rule2 = "New-AzNetworkSecurityRuleConfig" ascii wide
        $nsg_rule3 = "Set-AzNetworkSecurityRuleConfig" ascii wide
        $nsg_rule4 = "az network nsg rule" ascii wide
        $nsg_rule5 = "securityRules" ascii wide
        $nsg_rule6 = "NetworkSecurityGroupName" ascii wide
        $nsg_rule7 = "securityRule" ascii wide
        $nsg_rule8 = "networkSecurityGroups" ascii wide
        
        // Insecure NSG rule parameters
        $insecure_param1 = "SourceAddressPrefix \"*\"" ascii wide
        $insecure_param2 = "SourceAddressPrefix \"Internet\"" ascii wide
        $insecure_param3 = "DestinationAddressPrefix \"*\"" ascii wide
        $insecure_param4 = "Access \"Allow\"" ascii wide
        $insecure_param5 = "Direction \"Inbound\"" ascii wide
        $insecure_param6 = "Priority 100" ascii wide
        $insecure_param7 = "DestinationPortRange \"*\"" ascii wide
        $insecure_param8 = "DestinationPortRange \"22\"" ascii wide
        $insecure_param9 = "DestinationPortRange \"3389\"" ascii wide
        $insecure_param10 = "Protocol \"*\"" ascii wide
        
        // Public IP allocation
        $public_ip1 = "New-AzPublicIpAddress" ascii wide
        $public_ip2 = "az network public-ip create" ascii wide
        $public_ip3 = "publicIPAddresses" ascii wide
        $public_ip4 = "publicIPAddress" ascii wide
        $public_ip5 = "PublicIPAllocationMethod" ascii wide
        $public_ip6 = "BasicSku" ascii wide
        $public_ip7 = "StandardSku" ascii wide
        $public_ip8 = "Dynamic" ascii wide
        
        // Network peering
        $peering1 = "Add-AzVirtualNetworkPeering" ascii wide
        $peering2 = "New-AzVirtualNetworkPeering" ascii wide
        $peering3 = "az network vnet peering" ascii wide
        $peering4 = "virtualNetworkPeerings" ascii wide
        $peering5 = "AllowForwardedTraffic" ascii wide
        $peering6 = "AllowGatewayTransit" ascii wide
        $peering7 = "UseRemoteGateways" ascii wide
        $peering8 = "RemoteVirtualNetwork" ascii wide
        
        // Azure Firewall modifications
        $firewall1 = "New-AzFirewall" ascii wide
        $firewall2 = "Set-AzFirewall" ascii wide
        $firewall3 = "Remove-AzFirewall" ascii wide
        $firewall4 = "az network firewall" ascii wide
        $firewall5 = "AzureFirewallNetworkRule" ascii wide
        $firewall6 = "AzureFirewallApplicationRule" ascii wide
        $firewall7 = "AzureFirewallNatRule" ascii wide
        $firewall8 = "ThreatIntelMode \"Off\"" ascii wide
        
        // Suspicious network changes
        $susp_net1 = "delete network security group" nocase ascii wide
        $susp_net2 = "delete firewall" nocase ascii wide
        $susp_net3 = "allow all traffic" nocase ascii wide
        $susp_net4 = "allow any any" nocase ascii wide
        $susp_net5 = "bypass firewall" nocase ascii wide
        $susp_net6 = "open all ports" nocase ascii wide
        $susp_net7 = "disable security" nocase ascii wide
        $susp_net8 = "allow any inbound" nocase ascii wide
        
        // Network Watcher and diagnostic settings
        $watcher1 = "NetworkWatcher" ascii wide
        $watcher2 = "flowLogs" ascii wide
        $watcher3 = "networkWatchers" ascii wide
        $watcher4 = "connectionMonitors" ascii wide
        $watcher5 = "packetCaptures" ascii wide
        $watcher6 = "Disabled" ascii wide
        $watcher7 = "retention" ascii wide
        $watcher8 = "isEnabled = false" nocase ascii wide
        
        // Virtual Network Gateway and VPN
        $gateway1 = "VirtualNetworkGateway" ascii wide
        $gateway2 = "VpnClient" ascii wide
        $gateway3 = "LocalNetworkGateway" ascii wide
        $gateway4 = "VpnConnection" ascii wide
        $gateway5 = "RouteBased" ascii wide
        $gateway6 = "PolicyBased" ascii wide
        $gateway7 = "IkeEncryption" ascii wide
        $gateway8 = "IpsecEncryption" ascii wide
        
        // Suspicious gateway configurations
        $susp_gateway1 = "BasicSku" ascii wide
        $susp_gateway2 = "IkeEncryption \"DES\"" ascii wide
        $susp_gateway3 = "IkeIntegrity \"MD5\"" ascii wide
        $susp_gateway4 = "IpsecEncryption \"DES\"" ascii wide
        $susp_gateway5 = "IpsecIntegrity \"MD5\"" ascii wide
        $susp_gateway6 = "PfsGroup \"None\"" ascii wide
        $susp_gateway7 = "\"disableVpnEncryption\": true" ascii wide
        $susp_gateway8 = "DhGroup \"Group1\"" ascii wide
        
    condition:
        // Confirm it's related to Azure Networking
        (any of ($network_id*) or any of ($network_cli*)) and
        
        (
            // Insecure NSG rules
            (1 of ($nsg_rule*) and 2 of ($insecure_param*)) or
            
            // Public IP allocation with suspicious network changes
            (1 of ($public_ip*) and 1 of ($susp_net*)) or
            
            // Dangerous network peering configurations
            (1 of ($peering*) and 1 of ($susp_net*)) or
            
            // Firewall tampering
            (1 of ($firewall*) and (1 of ($susp_net*) or $firewall8)) or
            
            // Direct suspicious network configurations
            (1 of ($susp_net*)) or
            
            // Network monitoring disabling
            (1 of ($watcher*) and ($watcher6 or $watcher8)) or
            
            // Insecure VPN/Gateway configurations
            (1 of ($gateway*) and 1 of ($susp_gateway*)) or
            
            // Multiple insecure parameters
            (3 of ($insecure_param*))
        )
}