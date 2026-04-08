# Honeypot Use Case: Malware Collection, Execution, and Detection
![Fondos_INCIBE](https://github.com/nicslabdev/HoneyV/raw/main/logo_fondos_incibe.png)
<b>Estos resultados han sido (parcialmente) financiados por la Cátedra Internacional UMA 2023, la cual forma parte del Programa Global de Innovación en Seguridad para la promoción de Cátedras de Ciberseguridad en España financiado por la Unión Europea Fondos NextGeneration-EU, a través del Instituto Nacional de Ciberseguridad (INCIBE).</b>

## Overview

This repository serves as a comprehensive malware analysis framework that combines automated orchestration, hybrid analysis (static and dynamic), and systematic malware categorization. It contains **real malware samples** organized by families to facilitate cybersecurity research, threat intelligence, and malware behavior analysis using **honeypot-collected specimens**.

The project provides an end-to-end automated workflow for malware analysis, from sample acquisition through honeypot deployment to detailed forensic examination in isolated virtual environments.

## Repository Structure

The repository is organized into **8 major malware categories**, containing **65+ malware families** with real-world samples:

### Categories

- **Adwares/** (10 families): Adload, Auslogics, Generic, InstalleRex, InstallUnion, Koutodoor, LoadMoney, Neoreklami, Qjwmonkey, Techsnab
- **Botnet/** (5 families): Amadey, IRCbot, Lu0Bot, OriginBotnet, Quakbot
- **Gusanos/** (Worms, 4 families): Blaster, Magistr, MyDoom, Phorpiex, Sasser
- **Keyloggers/** (5 families): a310Logger, AgentTesla, MassLogger, SnakeKeyLogger, VIPKeyLogger
- **Ransomwares/** (9 families): Akira, BQTLock, Cephalus, Chaos, GlobeImposter, INC, Medusa, Petya, Vatican
- **Rootkits/** (5 families): DiskWritter, Duqu, FuRootkit, r77, ZeroAccess
- **Spywares/** (9 families): DarkCloud, DarkTortilla, GCleaner, HawkEye, Loki, LummaStelear, RedLineStealer, Rhadamanthys, Vidar
- **Troyanos/** (Trojans, 7 families): AsyncRAT, AtlasAgent, DarkVNC, GuLoader, IcedID, QuasarRAT, ValleyRAT
- **Virus/** (7 families): AntiExe, Brain, CIH, Hopper, Jerusalem, Junkie, Melissa

Each malware family contains:
- Actual malware binary (PE executable format for Windows)
- Metadata file (`Readme.md`) with SHA256/MD5 hashes and VirusTotal links

## ⚠️ Safety Warning

**CRITICAL**: This repository contains **real, dangerous malware samples**. 

- Samples must ONLY be handled in **isolated, air-gapped environments**
- Recommended: Use virtual machines (FlareVM) with no internet connectivity
- **ZIP password**: `infected`
- **File format**: Primarily Windows PE executables (`.exe`, `.dll`, `.sys`, `.scr`, `.com`, `.bin`)
- Improper handling can result in system compromise, data loss, or network infection

## Automation Scripts

The repository includes two PowerShell automation scripts that implement a complete malware analysis pipeline:

### 1. Analyzer.ps1
**Hybrid Malware Analysis Engine**

Performs comprehensive static and dynamic analysis on malware samples within a FlareVM environment:

#### Static Analysis
- **Hash Calculation**: MD5, SHA1, SHA256
- **String Extraction**: FLOSS (FireEye Labs Obfuscated String Solver) for extracting obfuscated/encrypted strings
- **Packer Detection**: Detect It Easy (DIEC) for identifying packers, compilers, and obfuscation techniques
- **Metadata Collection**: OS, compiler, language detection
- **Manual Analysis Support**: CFF Explorer (PE resources, manifests, certificates), Ghidra/Binary Ninja (decompilation)

#### Dynamic Analysis (Configurable Duration: 1-300 seconds)
- **Process Monitoring**: Procmon captures system calls, registry modifications, file operations
- **Memory Forensics**: ProcDump generates memory dumps for Volatility analysis
- **Network Simulation**: FakeNet-NG intercepts network communications
- **Traffic Capture**: Tshark/Wireshark PCAP generation for network behavior analysis
- **Behavioral Tracking**: Complete artifact collection for post-analysis

#### Output
Generates a comprehensive JSON report containing:
- Sample metadata (filename, size, hashes, acquisition timestamp)
- Environment details (FlareVM, T-Pot honeypot, network configuration)
- Static analysis results (strings count, packer signatures, compiler info)
- Dynamic analysis artifacts (Procmon logs, memory dumps, PCAPs, FakeNet logs)
- All artifacts archived in a ZIP file for transport

**Configurable Parameters**:
```powershell
.\Analyzer.ps1 -DynamicTime 120  # Run dynamic analysis for 120 seconds
```

### 2. Orchestrator.ps1
**Automated Sample Processing Orchestrator**

Manages the complete malware analysis lifecycle using VirtualBox automation:

#### Workflow
1. **Sample Queue Management**: Monitors `C:\LabShare\Malware` for pending samples
2. **VM State Control**: Manages FlareVM via VBoxManage CLI
3. **Snapshot Restoration**: Reverts to clean "baseline" snapshot before each analysis
4. **Analysis Execution**: Launches `Analyzer.ps1` inside the VM using VirtualBox Guest Control
5. **Report Monitoring**: Waits for analysis completion (JSON report generation)
6. **Cleanup**: Shuts down VM, deletes processed sample, prepares for next iteration
7. **Loop**: Continues until all samples are analyzed

#### Configuration
```powershell
$vmName       = "FlareVM"           # VirtualBox VM name
$snapshotName = "baseline"          # Clean snapshot identifier
$shareRoot    = "C:\LabShare"       # Shared folder for samples/reports
$guestUser    = "FlareVM"           # VM guest OS username
$guestPass    = "password"          # VM guest OS password
```

#### Features
- Automatic VM lifecycle management (start, snapshot restore, shutdown)
- Guest OS boot detection (waits for GuestAdditions RunLevel 3)
- Report generation verification
- Timeout handling (600 seconds per sample)
- Sequential processing with state isolation

## Technical Requirements

### Host System
- **OS**: Windows with PowerShell 5.1+
- **Hypervisor**: Oracle VirtualBox with Guest Additions
- **Storage**: Shared folder configuration between host and VM

### Guest VM (FlareVM)
- **Image**: FlareVM (FLARE VM malware analysis distribution)
- **Tools**: FLOSS, DIEC, Procmon, ProcDump, FakeNet-NG, Wireshark/Tshark
- **Network**: Isolated network adapter (for controlled analysis)
- **Snapshot**: Clean baseline snapshot for restoration

### Honeypot Integration
- **Platform**: T-Pot (multi-honeypot platform)
- **Purpose**: Malware sample collection from live attacks
- **Integration**: Samples transferred to analysis queue

## Use Cases

1. **Threat Intelligence**: Build malware signature databases from real-world samples
2. **Behavioral Analysis**: Study malware execution patterns, persistence mechanisms, C2 communications
3. **Detection Engineering**: Develop YARA rules, SIGMA rules, and IDS signatures
4. **Forensic Training**: Educational resource for malware analysis techniques
5. **Honeypot Research**: Automated processing of honeypot-captured threats
6. **Incident Response**: Rapid analysis pipeline for suspicious binaries

## Research Context

This framework was developed as part of a cybersecurity research project at Universidad de Málaga, focusing on:
- Automated malware analysis pipelines
- Honeypot-driven threat collection
- Hybrid analysis methodologies (static + dynamic)
- Reproducible malware research workflows

## Metadata Format

Each malware sample includes a standardized `Readme.md`:
```markdown
# [Malware Family Name]
- **SHA256**: [64-character hash]
- **MD5**: [32-character hash]
- **VirusTotal**: https://www.virustotal.com/gui/file/[SHA256]
```

## Legal & Ethical Notice

This repository is intended **exclusively for authorized cybersecurity research, education, and defensive security purposes**. Unauthorized distribution, execution, or use of these samples for malicious purposes is illegal and unethical. Users assume full responsibility for compliance with local laws and regulations.
