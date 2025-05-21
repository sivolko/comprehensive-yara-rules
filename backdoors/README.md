# Backdoor Detection Rules

This directory contains YARA rules for detecting backdoors, remote access trojans (RATs), and other persistent access tools.

## Categories

Rules in this directory are organized by backdoor family and persistence mechanism.

## Naming Convention

Rules follow this naming convention:
- `backdoor_[family]_[variant].yar` - For specific backdoor family detection
- `behavior_persistence_[technique].yar` - For persistence behavior patterns

## Testing

All rules should be tested against known samples to minimize false positives.