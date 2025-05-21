# APT Detection Rules

This directory contains YARA rules for detecting tools, malware, and techniques associated with Advanced Persistent Threat (APT) groups.

## Categories

Rules in this directory are organized by APT group and attack techniques.

## Naming Convention

Rules follow this naming convention:
- `apt_[group]_[tool/malware].yar` - For APT-specific tools/malware
- `apt_technique_[tactic].yar` - For techniques used across multiple APT groups

## Testing

All rules should be tested against known samples to minimize false positives.