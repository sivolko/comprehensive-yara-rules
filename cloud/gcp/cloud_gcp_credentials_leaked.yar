/*
   YARA Rule Set
   Author: Shubhendu Shubham
   Date: 2025-05-21
   Identifier: GCP Credentials
   Reference: https://cloud.google.com/docs/authentication
*/

rule cloud_gcp_credentials_leaked {
    meta:
        description = "Detects Google Cloud Platform credentials in files"
        author = "Shubhendu Shubham"
        date = "2025-05-21"
        reference = "https://cloud.google.com/docs/authentication"
        severity = "critical"
        
    strings:
        // GCP Service Account Key File patterns
        $json_key1 = "type" nocase ascii wide
        $json_key2 = "project_id" nocase ascii wide
        $json_key3 = "private_key_id" nocase ascii wide
        $json_key4 = "private_key" nocase ascii wide
        $json_key5 = "client_email" nocase ascii wide
        $json_key6 = "client_id" nocase ascii wide
        $json_key7 = "auth_uri" nocase ascii wide
        $json_key8 = "token_uri" nocase ascii wide
        
        // GCP private key patterns
        $private_key1 = "-----BEGIN PRIVATE KEY-----" ascii wide
        $private_key2 = "-----END PRIVATE KEY-----" ascii wide
        
        // Project ID patterns
        $project_id = /project[_-]id["']\s*[:=]\s*["'][a-z]([a-z0-9-])+["']/ nocase ascii wide
        
        // GCP service account naming patterns
        $sa_email = /[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com/ ascii wide
        
        // GCP API keys
        $api_key = /AIza[0-9A-Za-z\-_]{35}/ ascii wide
        
        // OAuth client IDs
        $oauth_id = /[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com/ ascii wide
        
        // GCP configuration contexts
        $gcp_context1 = "GOOGLE_APPLICATION_CREDENTIALS" ascii wide
        $gcp_context2 = "gcloud auth" ascii wide
        $gcp_context3 = "credentials.json" ascii wide
        $gcp_context4 = "googleCredentials" ascii wide
        $gcp_context5 = "ApplicationDefaultCredentials" ascii wide
        
        // GCP SDK related
        $gcp_sdk1 = "google-cloud" ascii wide
        $gcp_sdk2 = "google.cloud" ascii wide
        $gcp_sdk3 = "from google.cloud import" ascii wide
        $gcp_sdk4 = "require('google-cloud')" ascii wide
        $gcp_sdk5 = "import com.google.cloud" ascii wide
        
        // GCP token access or generation
        $token1 = "gcloud auth print-access-token" ascii wide
        $token2 = "generateAccessToken" ascii wide
        $token3 = "access_token" ascii wide
        
    condition:
        // Service account key file pattern - highest risk
        (all of ($json_key*)) or
        
        // Private key with service account email pattern
        ($private_key1 and $private_key2 and $sa_email) or
        
        // GCP API key in a GCP context
        ($api_key and any of ($gcp_context*)) or
        
        // OAuth client ID in a GCP context
        ($oauth_id and any of ($gcp_context*)) or
        
        // Explicit token handling with service account indicators
        (any of ($token*) and $sa_email) or
        
        // GCP SDK with credentials and project settings
        (2 of ($gcp_sdk*) and $project_id and any of ($gcp_context*))
}