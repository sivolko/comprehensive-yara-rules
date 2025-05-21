/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Azure Function Backdoor
   Reference: https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
*/

rule cloud_azure_function_backdoor {
    meta:
        description = "Detects potential backdoors in Azure Functions"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts"
        severity = "high"
        
    strings:
        // Command execution patterns
        $cmd_exec1 = "child_process" ascii wide
        $cmd_exec2 = "subprocess" ascii wide
        $cmd_exec3 = "os.system" ascii wide
        $cmd_exec4 = "os.popen" ascii wide
        $cmd_exec5 = "eval(" nocase ascii wide
        $cmd_exec6 = "exec(" nocase ascii wide
        $cmd_exec7 = "spawn(" nocase ascii wide
        $cmd_exec8 = "shell=True" ascii wide
        $cmd_exec9 = "Process.Start" ascii wide
        $cmd_exec10 = "ShellExecute" ascii wide
        
        // Network/Reverse Shell indicators
        $net1 = "socket.socket" ascii wide
        $net2 = "net.Socket" ascii wide
        $net3 = "net.connect" ascii wide
        $net4 = "reverse shell" ascii wide nocase
        $net5 = "TcpClient" ascii wide
        $net6 = "WebClient" ascii wide
        $net7 = "HttpClient" ascii wide
        $net8 = "System.Net.Sockets" ascii wide
        
        // Azure Function context
        $func1 = "function.json" ascii wide
        $func2 = "host.json" ascii wide
        $func3 = "Microsoft.Azure.WebJobs" ascii wide
        $func4 = "Microsoft.Azure.Functions" ascii wide
        $func5 = "AzureWebJobsStorage" ascii wide
        $func6 = "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING" ascii wide
        $func7 = "FUNCTIONS_WORKER_RUNTIME" ascii wide
        
        // Suspicious Azure Function code
        $susp1 = "GetEnvironmentVariable" ascii wide
        $susp2 = "Environment.GetEnvironmentVariable" ascii wide
        $susp3 = "process.env" ascii wide
        $susp4 = "os.environ" ascii wide
        
        // Suspicious Azure credential access
        $cred1 = "DefaultAzureCredential" ascii wide
        $cred2 = "ManagedIdentityCredential" ascii wide
        $cred3 = "ClientSecretCredential" ascii wide
        $cred4 = "AzureCliCredential" ascii wide
        $cred5 = "EnvironmentCredential" ascii wide
        
        // Data exfiltration patterns
        $exfil1 = "BlobClient" ascii wide
        $exfil2 = "UploadAsync" ascii wide
        $exfil3 = "fetch(" ascii wide
        $exfil4 = "https://" ascii wide
        $exfil5 = "http://" ascii wide
        $exfil6 = ".upload" ascii wide
        $exfil7 = "uploadBlob" ascii wide
        
        // Azure Identity manipulation
        $id1 = "Microsoft.Graph" ascii wide
        $id2 = "Microsoft.Identity" ascii wide
        $id3 = "AddUserAsync" ascii wide
        $id4 = "CreateUserAsync" ascii wide
        $id5 = "UpdateUserAsync" ascii wide
        
    condition:
        // Confirm it's an Azure Function
        any of ($func*) and
        
        (
            // Command execution with network activity
            (1 of ($cmd_exec*) and 1 of ($net*)) or
            
            // Suspicious identity activity
            (1 of ($cmd_exec*) and 1 of ($id*)) or
            
            // Data exfiltration patterns
            (1 of ($cmd_exec*) and 1 of ($exfil*)) or
            
            // Suspicious credential access with command execution
            (1 of ($cred*) and 1 of ($cmd_exec*)) or
            
            // Very suspicious network activity in Function
            (2 of ($net*)) or
            
            // Very suspicious identity manipulation
            (2 of ($id*))
        )
}