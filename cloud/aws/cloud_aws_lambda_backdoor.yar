/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: AWS Lambda Backdoor
   Reference: https://www.sans.org/blog/aws-lambda-security-best-practices/
*/

rule cloud_aws_lambda_backdoor {
    meta:
        description = "Detects potential backdoors in AWS Lambda functions"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://www.sans.org/blog/aws-lambda-security-best-practices/"
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
        $net7 = "nc -e" ascii wide
        $net8 = "bash -i" ascii wide
        
        // Lambda context
        $lambda1 = "lambda_handler" ascii wide
        $lambda2 = "exports.handler" ascii wide
        $lambda3 = "def handler" ascii wide
        $lambda4 = "context.function" ascii wide
        $lambda5 = "context.identity" ascii wide
        $lambda6 = "process.env.AWS_LAMBDA" ascii wide
        $lambda7 = "AWS_LAMBDA_FUNCTION_NAME" ascii wide
        
        // Suspicious lambda code - environment variable access
        $susp1 = "env.AWS_" ascii wide
        $susp2 = "process.env" ascii wide
        $susp3 = "os.environ" ascii wide
        
        // Suspicious lambda code - IAM/credential access
        $iam1 = "sts:AssumeRole" ascii wide
        $iam2 = "iam:" ascii wide
        $iam3 = "getCallerIdentity" ascii wide
        $iam4 = "iam.getUser" ascii wide
        $iam5 = "iam.createAccessKey" ascii wide
        
        // Data exfiltration patterns
        $exfil1 = "s3.putObject" ascii wide
        $exfil2 = "s3.upload" ascii wide
        $exfil3 = "fetch(" ascii wide
        $exfil4 = "https://" ascii wide
        $exfil5 = "http://" ascii wide
        
    condition:
        // Confirm it's a Lambda function
        any of ($lambda*) and
        
        (
            // Command execution with network activity
            (1 of ($cmd_exec*) and 1 of ($net*)) or
            
            // Suspicious IAM activity
            (1 of ($cmd_exec*) and 1 of ($iam*)) or
            
            // Data exfiltration patterns
            (1 of ($cmd_exec*) and 1 of ($exfil*)) or
            
            // Very suspicious network activity in Lambda
            (2 of ($net*)) or
            
            // Very suspicious IAM manipulation
            (2 of ($iam*))
        )
}