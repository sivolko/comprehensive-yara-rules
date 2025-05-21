# Information Stealer Detection Rules

This directory contains YARA rules for detecting information stealers that target credentials, sensitive data, and personal information.

## Categories

Rules in this directory are organized by information stealer family and target data type.

## Naming Convention

Rules follow this naming convention:
- `infostealer_[family]_[variant].yar` - For specific infostealer family detection
- `behavior_exfil_[technique].yar` - For data exfiltration behaviors

## Testing

All rules should be tested against known samples to minimize false positives.