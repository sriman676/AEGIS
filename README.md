# AEGIS

AEGIS is a **hostile-by-default**, AI-native workspace security and governed autonomous engineering platform.

This repository implements the production-grade security core and autonomous orchestration engine:

- **Hostile-by-Default Architecture**: All inputs are treated as malicious until validated.
- **Supply-Chain Integrity**: Multi-layered "Trust Fall" protection for AI IDE rule files.
- **Governed Orchestration**: Autonomous agents are restricted by a deterministic execution kernel.
- **Real-time Threat Monitoring**: Background `AEGIS Guardian` with native OS notifications.
- **Hardened Backend**: FastAPI with API key auth, rate limiting, and security middleware.

## Repository Layout

- `python/aegis-ai`: Hardened orchestration backend (FastAPI).
- `crates/aegis-core`: Deterministic Rust security engine (intake, analyzers, policy).
- `crates/aegis-cli`: Rust-based command-line interface.
- `dashboard/`: React-based observability and management interface.
- `.ai-plugins/`: Canonical master copies of AI IDE security rules.
- `.github/rulesets/`: Branch protection policies for supply-chain security.

## Security Controls

### 1. AI IDE Integrity (Trust Fall Protection)
AEGIS protects against malicious repo rule files using:
- **Integrity Lock**: `.ai-plugins.lock` stores SHA-256 hashes of all `.cursorrules`, `.clinerules`, etc.
- **CI Enforcement**: GitHub Actions block builds if rule files are modified without re-locking.
- **Branch Protection**: Enforced status checks prevent bypassing integrity guards.

### 2. Execution Sandbox
All agent commands are routed through:
- **Governance Engine**: Evaluates semantic risk and flags dangerous capabilities.
- **Deterministic Kernel**: Enforces an allowlist of commands and isolates execution via Subprocess or Docker.

### 3. Monitoring
- **AEGIS Guardian**: Background daemon providing desktop alerts for blocked attacks.
- **Audit Logging**: Persistent, rotating JSON logs for forensics and compliance.

## Quick Start

### Backend & Dashboard (Docker)
```bash
docker-compose up --build
```

### Manual Backend Install (Windows)
```powershell
./install.ps1
```

### Manual Backend Install (Linux/macOS)
```bash
./install.sh
```

## Core Invariants

- Hostile-by-default is mandatory.
- Deterministic enforcement is mandatory.
- No execution without governed routing.
- No AI policy authority (AI is advisory only).
- Explainability and auditability are mandatory.
