# Webshell Detection Rules

This directory contains YARA rules for detecting various types of webshells across different web technologies.

## Categories

Rules in this directory are organized by programming language and webshell functionality.

## Naming Convention

Rules follow this naming convention:
- `webshell_[language]_[family/functionality].yar` - For specific webshell detection
- `generic_webshell_[language].yar` - For generic webshell patterns in a specific language

## Testing

All rules should be tested against known samples to minimize false positives.