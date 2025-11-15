# Network Exposure Assessment Tool

Automated Nmap scanning, XML parsing, and security risk classification for early-stage reconnaissance and network exposure assessment.

The **Network Exposure Assessment Tool** is a Python-based helper that performs a targeted Nmap scan, parses the XML output, identifies exposed services, assigns risk levels, and generates a clear, human-readable Markdown report.

It is designed to support security analysts, penetration testers, and engineers who need a quick, repeatable way to understand a host’s attack surface and prioritise high-risk services.

---

## Features

- 🔍 **Automated Nmap Execution**  
  Runs Nmap with service and OS detection flags (`-sV`, `-O`, `-T4`) and consumes the XML output directly.

- 🧩 **Structured XML Parsing**  
  Extracts host IP, open ports, protocol, and service information using Python’s `xml.etree.ElementTree`.

- ⚠️ **Risk Classification per Port**  
  Maps open ports to risk levels (e.g. HIGH / MEDIUM) with clear, human-readable reasons based on common attack patterns and misconfigurations.

- 📄 **Markdown Exposure Report**  
  Generates `report.md`, summarising open ports, associated services, risk level, and explanatory context.

- 🛠️ **Extensible Design**  
  Modular functions that can be extended to output HTML, JSON, or integrate with other tooling.

---

## Requirements

**System**

- Linux (Kali recommended), macOS, or WSL
- Nmap 7.x or later installed and available in `PATH`
- Python 3.9+ (tested with Python 3.13)

**Python Libraries**

Uses only the standard library:

- `subprocess`
- `xml.etree.ElementTree`
- `pathlib`

No third-party dependencies are required.

---

## Usage

### 1. Clone the Repository

```bash
git clone https://github.com/Voy6/network-exposure-tool.git
cd network-exposure-tool
