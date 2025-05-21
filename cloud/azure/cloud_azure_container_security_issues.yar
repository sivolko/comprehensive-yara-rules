/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Container Security
   Reference: https://learn.microsoft.com/en-us/azure/container-instances/container-instances-security
*/

rule cloud_azure_container_security_issues {
    meta:
        description = "Detects security issues in Azure Container Instances and Azure Kubernetes Service"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/container-instances/container-instances-security"
        severity = "high"
        
    strings:
        // Azure Container identification strings
        $container_id1 = "Microsoft.ContainerInstance" ascii wide
        $container_id2 = "Microsoft.ContainerRegistry" ascii wide
        $container_id3 = "Microsoft.ContainerService" ascii wide
        $container_id4 = "Microsoft.KubernetesConfiguration" ascii wide
        $container_id5 = "AzureContainerInstances" ascii wide
        $container_id6 = "ContainerInstances" ascii wide
        $container_id7 = "ContainerService" ascii wide
        $container_id8 = "AzureContainerRegistry" ascii wide
        
        // Container SDKs and libraries
        $container_sdk1 = "Azure.ResourceManager.ContainerInstance" ascii wide
        $container_sdk2 = "Azure.ResourceManager.ContainerRegistry" ascii wide
        $container_sdk3 = "Azure.ResourceManager.ContainerService" ascii wide
        $container_sdk4 = "Microsoft.Azure.Management.ContainerInstance" ascii wide
        $container_sdk5 = "Microsoft.Azure.Management.ContainerRegistry" ascii wide
        $container_sdk6 = "Microsoft.Azure.Management.ContainerService" ascii wide
        
        // CLI tools and commands
        $container_cli1 = "az container" ascii wide
        $container_cli2 = "az acr" ascii wide
        $container_cli3 = "az aks" ascii wide
        $container_cli4 = "kubectl" ascii wide
        $container_cli5 = "docker" ascii wide
        $container_cli6 = "New-AzContainerGroup" ascii wide
        $container_cli7 = "New-AzContainerRegistry" ascii wide
        $container_cli8 = "New-AzAksCluster" ascii wide
        
        // Security misconfigurations - Container Instances
        $aci_misconf1 = "privileged = true" nocase ascii wide
        $aci_misconf2 = "--command-line" ascii wide
        $aci_misconf3 = "containerPort = 22" nocase ascii wide
        $aci_misconf4 = "containerPort = 3389" nocase ascii wide
        $aci_misconf5 = "PrivateIpAddress =" nocase ascii wide
        $aci_misconf6 = "environmentVariable " nocase ascii wide
        $aci_misconf7 = ".secrets" nocase ascii wide
        $aci_misconf8 = "secureValue" nocase ascii wide
        
        // Security misconfigurations - AKS
        $aks_misconf1 = "enableRBAC = false" nocase ascii wide
        $aks_misconf2 = "enablePrivateCluster = false" nocase ascii wide
        $aks_misconf3 = "aadProfileManaged = false" nocase ascii wide
        $aks_misconf4 = "apiServerAuthorizedIpRanges = nil" nocase ascii wide
        $aks_misconf5 = "azureKeyVaultKms = false" nocase ascii wide
        $aks_misconf6 = "networkPlugin = \"kubenet\"" nocase ascii wide
        $aks_misconf7 = "NetworkPolicy = \"\"" nocase ascii wide
        $aks_misconf8 = "enablePodSecurityPolicy = false" nocase ascii wide
        
        // Security misconfigurations - ACR
        $acr_misconf1 = "adminUserEnabled = true" nocase ascii wide
        $acr_misconf2 = "anonymousPullEnabled = true" nocase ascii wide
        $acr_misconf3 = "publicNetworkAccess = \"Enabled\"" nocase ascii wide
        $acr_misconf4 = "publicNetworkEnabled = true" nocase ascii wide
        $acr_misconf5 = "dataEndpointEnabled = false" nocase ascii wide
        $acr_misconf6 = "quarantinePolicy.status = \"disabled\"" nocase ascii wide
        $acr_misconf7 = "trustPolicy.status = \"disabled\"" nocase ascii wide
        $acr_misconf8 = "retentionPolicy = nil" nocase ascii wide
        
        // Container escape and privilege escalation techniques
        $container_attack1 = "mount /dev" nocase ascii wide
        $container_attack2 = "mount proc" nocase ascii wide
        $container_attack3 = "setns" nocase ascii wide
        $container_attack4 = "syscall" nocase ascii wide
        $container_attack5 = "CAP_SYS_ADMIN" nocase ascii wide
        $container_attack6 = "hostPath" nocase ascii wide
        $container_attack7 = "privileged: true" nocase ascii wide
        $container_attack8 = "allowPrivilegeEscalation: true" nocase ascii wide
        $container_attack9 = "hostPID: true" nocase ascii wide
        $container_attack10 = "hostNetwork: true" nocase ascii wide
        
        // Container backdoor patterns
        $container_backdoor1 = "COPY backdoor" nocase ascii wide
        $container_backdoor2 = "RUN curl http" nocase ascii wide
        $container_backdoor3 = "RUN wget http" nocase ascii wide
        $container_backdoor4 = "ncat" nocase ascii wide
        $container_backdoor5 = "netcat" nocase ascii wide
        $container_backdoor6 = "reverse shell" nocase ascii wide
        $container_backdoor7 = "nc -e" nocase ascii wide
        $container_backdoor8 = "listen(" nocase ascii wide
        
        // Suspicious container commands
        $container_susp1 = "az acr repository delete" ascii wide
        $container_susp2 = "az acr run" ascii wide
        $container_susp3 = "docker run --net=host" ascii wide
        $container_susp4 = "kubectl exec" ascii wide
        $container_susp5 = "kubectl cp" ascii wide
        $container_susp6 = "kubectl create secret" ascii wide
        $container_susp7 = "kubectl delete" ascii wide
        $container_susp8 = "docker save" ascii wide
        
    condition:
        // Confirm it's related to Azure containers
        (any of ($container_id*) or any of ($container_sdk*) or any of ($container_cli*)) and
        
        (
            // Container Instances misconfigurations
            (2 of ($aci_misconf*)) or
            
            // AKS misconfigurations
            (2 of ($aks_misconf*)) or
            
            // ACR misconfigurations
            (2 of ($acr_misconf*)) or
            
            // Container escape techniques
            (1 of ($container_attack*)) or
            
            // Container backdoor
            (1 of ($container_backdoor*)) or
            
            // Suspicious container operations combined with misconfigurations
            (1 of ($container_susp*) and (
                1 of ($aci_misconf*) or 
                1 of ($aks_misconf*) or 
                1 of ($acr_misconf*)
            ))
        )
}