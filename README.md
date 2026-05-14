<div align="center">

# 🛡️ AEGIS Security Platform

**The Hostile-by-Default, AI-Native Workspace Security & Autonomous Engineering Engine**

[![AEGIS CI/CD](https://github.com/sriman676/AEGIS/actions/workflows/ci.yml/badge.svg)](https://github.com/sriman676/AEGIS/actions/workflows/ci.yml)
[![CodeQL Security Analysis](https://github.com/sriman676/AEGIS/actions/workflows/codeql.yml/badge.svg)](https://github.com/sriman676/AEGIS/actions/workflows/codeql.yml)
[![Trivy Scan](https://github.com/sriman676/AEGIS/actions/workflows/trivy.yml/badge.svg)](https://github.com/sriman676/AEGIS/actions/workflows/trivy.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

*AEGIS acts as an impenetrable shield for AI-driven software development, ensuring that agents operate within strict, verifiable, and deterministic boundaries.*

[Documentation](#) • [Quick Start](#-quick-start) • [Report a Bug](#) • [Request Feature](#)
</div>

---

## 📖 Table of Contents
- [Why AEGIS?](#-why-aegis)
- [Key Features](#-key-features)
- [Repository Architecture](#-repository-architecture)
- [Quick Start](#-quick-start)
- [Security Controls & Invariants](#-security-controls--invariants)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚡ Why AEGIS?

As coding environments become increasingly autonomous and AI-driven, the attack surface expands. Malicious prompt injections, supply-chain exploits, and rogue AI agents present a new frontier of vulnerabilities.

**AEGIS solves this by implementing a zero-trust, hostile-by-default execution kernel.** We don't just detect threats; we deterministically prevent unauthorized execution and strictly govern autonomous behaviors inside your workspace.

> **Our Philosophy**: *All inputs, prompts, and codebase contexts are aggressively challenged and treated as malicious until cryptographically or deterministically validated.*

---

## 🌟 Key Features

- 🛡️ **Hostile-by-Default Architecture**: Every command is assumed malicious.
- 🔗 **Supply-Chain Integrity (Trust Fall)**: Immutable locking and multi-layered protection for AI IDE rule files (`.clinerules`, `.cursorrules`, etc.).
- 🧠 **Governed Orchestration**: Autonomous agents are restricted by a deterministic Execution Kernel. *AI systems have no direct policy authority.*
- 👁️ **Real-Time Threat Monitoring**: `AEGIS Guardian` runs silently in the background, providing native OS notifications for blocked attacks.
- ⚡ **Hardened Multi-Language Stack**: A seamless integration of a Python/FastAPI backend, a blazingly fast Rust security engine, and a React observability dashboard.
- 🗄️ **Comprehensive Audit Tracking**: Persistent, rotating JSON logs mapped chronologically for incident forensics and compliance.

---

## 🏗️ Repository Architecture

The AEGIS workspace is built as a highly optimized polyglot monorepo:

```text
aegis/
├── 🦀 crates/                 # Deterministic Rust security engine
│   ├── aegis-core/            # Analysis, intake, policy evaluation, and events
│   └── aegis-cli/             # Ultra-fast Rust CLI for manual security intake
├── 🐍 python/aegis-ai/        # Hardened orchestration backend
│   ├── src/                   # FastAPI server, Governance engine, Sandbox kernel
│   └── tools/                 # Trust Fall integrity lock scripts
├── ⚛️ dashboard/               # React & Vite-based observability UI
├── 🔒 .ai-plugins/            # Canonical master copies of AI IDE security rules
└── 🛡️ .github/                # Branch protection and exhaustive CI/CD workflows
```

---

## 🚀 Quick Start

Launch the full AEGIS suite (Backend + Dashboard) natively or in a containerized sandbox.

### Option 1: Docker (Recommended for Sandboxing)
Ensure Docker and Docker Compose are installed.
```bash
# Clone the repository
git clone https://github.com/your-org/aegis.git
cd aegis

# Build and spin up the containers
docker-compose up --build
```
> 💡 **Tip:** The Dashboard will be accessible at `http://localhost:3000` and the API at `http://localhost:8000`.

### Option 2: Native Install (Windows)
We provide an automated setup script for PowerShell environments.
```powershell
./install.ps1
```

### Option 3: Native Install (Linux / macOS)
For Unix-based environments, use the bash setup script.
```bash
chmod +x install.sh
./install.sh
```

---

## 🛡️ Security Controls & Invariants

AEGIS operates on uncompromising kernel boundaries to protect your infrastructure.

### 1. AI IDE Integrity (Trust Fall Protection)
AEGIS directly protects against malicious repository rule files that attempt to socially engineer AI assistants.
- **Integrity Lock**: `.ai-plugins.lock` stores SHA-256 hashes of all relevant rule files.
- **CI Enforcement**: GitHub Actions immediately block builds if rule files are modified without re-locking the cache.

### 2. Execution Sandbox
All agent commands and systemic interactions flow strictly through AEGIS routers.
- **Governance Engine**: Evaluates semantic risk and flags dangerous capability combinations.
- **Deterministic Kernel**: Enforces an explicit allowlist of commands and systematically isolates execution via Subprocess or Docker.

### 🔬 Core Operating Invariants
- 🚫 **Hostile-by-default is mandatory.**
- ⚙️ **Deterministic enforcement is mandatory.**
- 🛑 **No execution without governed routing.**
- 🤖 **No AI policy authority (AI is advisory only).**
- 📜 **Explainability and chronological auditability are mandatory.**

---

## 🤝 Contributing

We welcome contributions from the community to strengthen the AEGIS shield! 

1. Read our [CONTRIBUTING.md](CONTRIBUTING.md) to set up your dev environment.
2. Review our [SECURITY.md](SECURITY.md) guidelines for vulnerability reporting.
3. Fork the repository, make your changes, and submit a PR!

---

## 📄 License

AEGIS is open-sourced under the [Apache License 2.0](LICENSE).
