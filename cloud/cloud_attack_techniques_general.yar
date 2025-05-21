/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: Cloud Attack Techniques
   Reference: https://attack.mitre.org/matrices/enterprise/cloud/
*/

rule cloud_attack_techniques_general {
    meta:
        description = "Detects common cloud attacker techniques that work across multiple cloud providers"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://attack.mitre.org/matrices/enterprise/cloud/"
        severity = "high"
        
    strings:
        // Credential Theft Techniques
        $cred_theft1 = "curl -H Metadata" ascii wide
        $cred_theft2 = "metadata.google.internal" ascii wide
        $cred_theft3 = "169.254.169.254" ascii wide // AWS/GCP metadata IP
        $cred_theft4 = "metadata.azure.internal" ascii wide
        $cred_theft5 = "169.254.170.2" ascii wide // ECS metadata
        $cred_theft6 = ".amazonaws.com/token" ascii wide
        $cred_theft7 = "X-aws-ec2-metadata-token" ascii wide
        $cred_theft8 = "Metadata-Flavor" ascii wide
        
        // Cloud privilege escalation
        $priv_esc1 = "iam.serviceAccounts.actAs" ascii wide
        $priv_esc2 = "iam:PassRole" ascii wide
        $priv_esc3 = "iam:UpdateAssumeRolePolicy" ascii wide
        $priv_esc4 = "AssignmentEligible" ascii wide
        $priv_esc5 = "elevateAccess" ascii wide
        $priv_esc6 = "Microsoft.Authorization/roleAssignments" ascii wide
        $priv_esc7 = "AzureADPrivilegedIdentity" ascii wide
        
        // Suspicious IAM / role creation
        $iam_create1 = "new-AzRoleAssignment" ascii wide
        $iam_create2 = "gcloud iam service-accounts create" ascii wide
        $iam_create3 = "aws iam create-user" ascii wide
        $iam_create4 = "aws iam attach-user-policy" ascii wide
        $iam_create5 = "New-AzADServicePrincipal" ascii wide
        $iam_create6 = "createServiceAccountKey" ascii wide
        
        // Cloud persistence
        $persist1 = "cronjob" ascii wide
        $persist2 = "terraform" ascii wide
        $persist3 = "CloudFormation" ascii wide
        $persist4 = "DeploymentManager" ascii wide
        $persist5 = "ARM template" ascii wide
        $persist6 = "EventBridge" ascii wide
        $persist7 = "ScheduledQuery" ascii wide
        $persist8 = "Cloud Scheduler" ascii wide
        
        // Suspicious cloud commands/scripts
        $cmd1 = "aws s3 cp" ascii wide
        $cmd2 = "gsutil cp" ascii wide
        $cmd3 = "az storage blob upload" ascii wide
        $cmd4 = "exfiltration" ascii wide nocase
        $cmd5 = "backdoor" ascii wide nocase
        $cmd6 = "gcloud config set" ascii wide
        $cmd7 = "aws configure" ascii wide
        $cmd8 = "az configure" ascii wide
        
        // Cloud API abuse patterns
        $api1 = "lambda:InvokeFunction" ascii wide
        $api2 = "functions.projects.locations.functions.call" ascii wide
        $api3 = "Microsoft.Web/sites/functions/action" ascii wide
        $api4 = "secretsmanager:GetSecretValue" ascii wide
        $api5 = "secrets.versions.access" ascii wide
        $api6 = "key-vault-secrets:list" ascii wide
        
        // Attack tool references
        $tool1 = "Pacu" ascii wide nocase
        $tool2 = "Cloudsploit" ascii wide nocase
        $tool3 = "ScoutSuite" ascii wide nocase
        $tool4 = "Microburst" ascii wide nocase
        $tool5 = "MicroBurst" ascii wide nocase
        $tool6 = "Gato" ascii wide nocase // GCP attack tool
        $tool7 = "CloudGoat" ascii wide nocase
        $tool8 = "weirdAAL" ascii wide nocase
        
    condition:
        // Different combinations of cloud attack techniques
        (
            // Basic credential theft attempts
            2 of ($cred_theft*) or
            
            // Privilege escalation attempts
            2 of ($priv_esc*) or
            
            // IAM entity creation with privilege escalation
            (any of ($iam_create*) and any of ($priv_esc*)) or
            
            // Suspicious cloud commands
            (2 of ($cmd*)) or
            
            // API abuse patterns
            (2 of ($api*)) or
            
            // Known attack tool indicators
            any of ($tool*) or
            
            // Persistence with credential theft
            (any of ($persist*) and any of ($cred_theft*))
        )
}