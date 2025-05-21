# Ransomware Detection Rules

This directory contains YARA rules for detecting different ransomware families and ransomware behavior patterns.

## Categories

Rules in this directory are organized by ransomware family or behavioral indicators.

## Naming Convention

Rules follow this naming convention:
- `ransomware_[family]_[variant].yar` - For specific ransomware family detection
- `behavior_ransom_[technique].yar` - For ransomware behavior patterns

## Testing

All rules should be tested against known samples to minimize false positives.