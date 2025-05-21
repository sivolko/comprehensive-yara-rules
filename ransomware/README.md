# Ransomware Detection Rules

This directory contains YARA rules for detecting different ransomware families and ransomware behavior patterns.

## Architecture

```mermaid
flowchart TD
    Ransomware[Ransomware Detection Rules] --> Families[Ransomware Families]
    Ransomware --> Behaviors[Ransomware Behaviors]
    
    Families --> Modern[Modern Ransomware]
    Families --> Legacy[Legacy Ransomware]
    Families --> RaaS[Ransomware-as-a-Service]
    
    Behaviors --> Encryption[Encryption Techniques]
    Behaviors --> Exfil[Data Exfiltration]
    Behaviors --> Cleanup[Anti-Recovery Techniques]
    Behaviors --> Persistence[Persistence Mechanisms]
    Behaviors --> Comm[Command & Control]
    
    Modern --> LockBit[LockBit Variants]
    Modern --> Conti[Conti Variants]
    Modern --> BlackCat[BlackCat/ALPHV]
    Modern --> BlackBasta[Black Basta]
    
    Legacy --> WannaCry[WannaCry]
    Legacy --> Ryuk[Ryuk]
    Legacy --> GandCrab[GandCrab]
    
    RaaS --> DarkSide[DarkSide]
    RaaS --> REvil[REvil/Sodinokibi]
    RaaS --> AvosLocker[AvosLocker]
    
    LockBit --> LockBitRule[ransomware_lockbit_3.yar]
    
    style LockBitRule fill:#90EE90
```

## Detection Techniques

| Technique | Description | Indicators |
|-----------|-------------|------------|
| **File Characteristics** | File markers and known patterns | Magic bytes, file headers, encryption signatures |
| **Behavioral Indicators** | Code behavior that suggests ransomware | File enumeration, encryption loops, shadow copy deletion |
| **Ransom Notes** | Detecting common ransom notes | Text patterns, HTML templates, wallpaper changers |
| **C2 Communication** | Command & control patterns | HTTP patterns, TOR connections, specific domains |
| **Post-Encryption** | Actions taken after encryption | Desktop changes, persistence mechanisms, cleanup routines |

## Categories

Rules in this directory are organized by ransomware family or behavioral indicators.

## Naming Convention

Rules follow this naming convention:
- `ransomware_[family]_[variant].yar` - For specific ransomware family detection
- `behavior_ransom_[technique].yar` - For ransomware behavior patterns

## Testing

All rules should be tested against known samples to minimize false positives.
