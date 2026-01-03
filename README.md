# ⚔️ Doppel

> **The Logic-Aware API Security Scanner.**
> Automatically detects BOLA (Broken Object Level Authorization) vulnerabilities by understanding API semantics, not just fuzzing IDs.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)
![AI](https://img.shields.io/badge/AI-Local_Privacy_First-purple.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

## 🧠 How Doppel is Different

Most scanners blindly fuzz every number they see (`page=1` → `page=2`). Doppel uses a **Semantic Risk Engine** to identify actual vulnerability candidates:

1.  **Semantic Risk Scoring:** * Analyzes parameter names and context (path vs body) to assign a **BOLA Risk Score (0-100)**.
    * *Example:* `userId` in a `GET` path is rated **Critical Risk**, while `limit=10` in a query is ignored.
2.  **Smart Mutation:**
    * Generates context-aware payloads: adjacent IDs (`user_123` → `user_124`), boundary values (`0`, `admin`), and type-specific fuzzing.
3.  **Weighted Verdicts:**
    * Distinguishes between **Reflection** (safe) and **Leakage** (vulnerable). 
    * *Example:* Seeing `created_by: "victim"` in a public post is safe. Seeing `id: "victim"` in a private profile object is a vulnerability.

## 🔒 Privacy-First Architecture

Doppel is designed for sensitive environments. 
* **Local-First:** Defaults to running entirely offline.
* **Ollama Integration:** Optional PII detection runs on your local machine (via `localhost:11434`). **Zero data is sent to the cloud.**

## 🚀 Quick Start

### Installation

```bash
# Via Cargo
cargo install --git https://github.com/abendrothj/doppel

# Or build from source (Recommended for M4/Apple Silicon)
git clone https://github.com/abendrothj/doppel
cd doppel
cargo build --release
```

### Usage

**1. Basic Scan (Postman/Bruno/OpenAPI)**

```bash
doppel \
  --input "./api-specs/openapi.json" \
  --base-url "https://api.target.com" \
  --attacker-token "eyJhbGc..." \
  --victim-id "user_123"
```

**2. With AI PII Detection (Requires Ollama)**

```bash
# First, ensure Ollama is running
ollama serve

# Run scan
doppel -i specs/ -b https://api.local -a $TOKEN -v 123 --enable-pii-analysis
```

## 🛠️ Features

* [x] **Zero-Config Discovery:** Parses Bruno (`.bru`), Postman, and OpenAPI files automatically.
* [x] **Logic-Aware Attacks:** Identifies and swaps resource IDs based on semantic weight.
* [x] **Weighted Verdict Engine:** Reduces false positives by analyzing JSON field importance.
* [x] **CI/CD Ready:** Returns exit code `1` on vulnerabilities; outputs CSV/Markdown/SARIF.

## 📦 CI/CD Integration

Doppel is designed to run in GitHub Actions. See `.github/workflows/security-scan.yml` for examples.

## 🤝 Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for details on the architecture.

**License:** MIT
