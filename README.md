# PyShield-Process-Guard (Mini EDR)

A lightweight Python-based endpoint security monitoring tool designed to demonstrate automated threat detection, process isolation, and incident logging principles.

## Architecture & Core Features
- **Real-Time Process Monitoring:** Utilizes system utilities to inspect active background processes and command-line arguments continuously.
- **Behavioral Pattern Matching:** Evaluates running processes against a configurable blocklist of threat indicators and malicious keywords.
- **Automated Incident Response:** Instantly issues termination commands (`terminate`/`kill`) to neutralize flagged processes based on Process IDs (PIDs).
- **Audit Logging:** Generates structured security telemetry records for incident review.

## Tech Stack
- **Language:** Python 3.x
- **Libraries:** `psutil` (Process and System Utilities)

## Installation & Execution
1. Ensure Python 3.x is installed on your machine.
2. Install the required dependency:
   ```bash
   pip install psutil
