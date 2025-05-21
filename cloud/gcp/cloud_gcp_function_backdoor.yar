/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: GCP Cloud Function Backdoor
   Reference: https://cloud.google.com/functions/docs/securing
*/

rule cloud_gcp_function_backdoor {
    meta:
        description = "Detects potential backdoors in GCP Cloud Functions"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://cloud.google.com/functions/docs/securing"
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
        
        // Network/Reverse Shell indicators
        $net1 = "socket.socket" ascii wide
        $net2 = "net.Socket" ascii wide
        $net3 = "net.connect" ascii wide
        $net4 = "reverse shell" ascii wide nocase
        $net5 = "connect(" ascii wide
        $net6 = ".listen(" ascii wide
        $net7 = "bash -i" ascii wide
        $net8 = "http.createServer" ascii wide
        
        // GCP Cloud Function context
        $gcp_func1 = "functions.CloudFunction" ascii wide
        $gcp_func2 = "functions.HttpFunction" ascii wide
        $gcp_func3 = "exports.entryPoint" ascii wide
        $gcp_func4 = "exports.handler" ascii wide
        $gcp_func5 = "@functions_framework.http" ascii wide
        $gcp_func6 = "req, res" ascii wide
        $gcp_func7 = "cloud.google.com/go/functions" ascii wide
        $gcp_func8 = "cloud.functions" ascii wide
        
        // Suspicious GCP function code - environment access
        $susp1 = "process.env" ascii wide
        $susp2 = "os.environ" ascii wide
        $susp3 = "System.getenv" ascii wide
        
        // Suspicious cloud function code - Metadata access
        $metadata1 = "metadata.google.internal" ascii wide
        $metadata2 = "computeMetadata" ascii wide
        $metadata3 = "instance/service-accounts" ascii wide
        $metadata4 = "Metadata-Flavor: Google" ascii wide
        
        // IAM related activities
        $iam1 = "google.iam" ascii wide
        $iam2 = "google.cloud.iam" ascii wide
        $iam3 = "setIamPolicy" ascii wide
        $iam4 = "getIamPolicy" ascii wide
        
        // Data exfiltration patterns
        $exfil1 = "storage.bucket" ascii wide
        $exfil2 = "storage.objects.create" ascii wide
        $exfil3 = "upload(" ascii wide
        $exfil4 = "https://" ascii wide
        $exfil5 = "http://" ascii wide
        $exfil6 = "fetch(" ascii wide
        
        // Cloud function configuration
        $config1 = "gcloud functions deploy" ascii wide
        $config2 = "google.cloud.functions.v1" ascii wide
        $config3 = "CloudFunctionsServiceClient" ascii wide
        
    condition:
        // Confirm it's a GCP Cloud Function
        any of ($gcp_func*) and
        
        (
            // Command execution with network activity
            (1 of ($cmd_exec*) and 1 of ($net*)) or
            
            // Suspicious metadata access with command execution
            (1 of ($metadata*) and 1 of ($cmd_exec*)) or
            
            // IAM manipulation with command execution
            (1 of ($iam*) and 1 of ($cmd_exec*)) or
            
            // Data exfiltration patterns with command execution
            (1 of ($exfil*) and 1 of ($cmd_exec*)) or
            
            // Very suspicious network activity in Cloud Function
            (2 of ($net*)) or
            
            // Very suspicious IAM manipulation
            (2 of ($iam*))
        )
}