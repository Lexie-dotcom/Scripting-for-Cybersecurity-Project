# Process and Network Connections Enumeration Tool
---

## Requirements/Setup Instructions
- Python
- PowerShell
- Windows Host System (Only tested on Windows)
---
Extract this repo into a folder and run ```python pip install -r requirements.txt``` to ensure that dependencies are satisfied.

## How to run
- Run .\orchestrator.ps1 from the PowerShell command line, it will work as both a standard user and administrator, but more information can be gathered if ran as administrator.
---
## Output files
- **IP Addresses.png** - Bar chart of IP addresses and how many connections are made to each address.
- **report.md** - Report in markdown format.
- **ps_output.json** - Raw data from PowerShell which is used by Python script, could be useful for further analysis by an administrator because additional data is included in this.
