# Cloud Infrastructure YARA Rules

This directory contains YARA rules for detecting threats, misconfigurations, and compromised resources in cloud environments.

## Categories

Rules in this directory are organized by cloud provider and resource type:

- `aws/` - Rules for Amazon Web Services resources and services
- `azure/` - Rules for Microsoft Azure resources and services
- `gcp/` - Rules for Google Cloud Platform resources and services

## Naming Convention

Rules follow this naming convention:
- `cloud_[provider]_[service]_[threat].yar` - For cloud provider-specific threat detection
- `cloud_[provider]_[config]_misconfig.yar` - For misconfiguration detection

## Use Cases

These rules can be used to detect:
- Credentials and tokens in application code and configurations
- Backdoored cloud functions/serverless resources
- Malicious cloud deployment templates
- Cloud-specific attack patterns
- Compromised cloud resources

## Testing

All rules should be tested to minimize false positives.