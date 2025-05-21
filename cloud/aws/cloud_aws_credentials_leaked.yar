/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: AWS Credentials
   Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
*/

rule cloud_aws_credentials_leaked {
    meta:
        description = "Detects AWS access keys in files"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        severity = "critical"
        
    strings:
        // AWS Access Key IDs
        $aws_access_key_id1 = /AKIA[0-9A-Z]{16}/ ascii wide
        $aws_access_key_comment1 = "aws_access_key_id" nocase ascii wide
        $aws_access_key_comment2 = "accesskeyid" nocase ascii wide
        $aws_access_key_comment3 = "access_key_id" nocase ascii wide
        
        // AWS Secret Access Keys
        $aws_secret1 = /"[^"]{40}"/
        $aws_secret_comment1 = "aws_secret_access_key" nocase ascii wide
        $aws_secret_comment2 = "secretaccesskey" nocase ascii wide
        $aws_secret_comment3 = "aws_secret" nocase ascii wide
        
        // AWS Session Tokens
        $aws_session_token1 = "aws_session_token" nocase ascii wide
        $aws_session_token2 = "sessiontoken" nocase ascii wide
        
        // AWS Configuration contexts
        $aws_context1 = "[default]" ascii wide
        $aws_context2 = "[profile " ascii wide
        $aws_context3 = "aws configure" ascii wide
        $aws_context4 = ".aws/credentials" ascii wide
        $aws_context5 = ".aws/config" ascii wide
        
        // AWS CLI Commands
        $aws_cli1 = "aws sts" ascii wide
        $aws_cli2 = "aws s3" ascii wide
        $aws_cli3 = "aws ec2" ascii wide
        
    condition:
        // The most important match pattern - actual access key with identifier
        ($aws_access_key_id1 and any of ($aws_secret*)) or
        
        // AWS configuration context with access key identifiers
        (any of ($aws_context*) and (any of ($aws_access_key_comment*) or any of ($aws_secret_comment*))) or
        
        // CLI contexts with credentials
        (any of ($aws_cli*) and $aws_access_key_id1)
}