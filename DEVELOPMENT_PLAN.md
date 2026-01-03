# 🗺️ Development Plan: Doppel

**Objective:** Build a high-performance, open-source security tool to detect BOLA/IDOR vulnerabilities in Fintech APIs.
**Current Release:** v1.0.0 (Official Release)

## 🟢 Phase 1: The Core (Parsers & Models) ✅ COMPLETED
**Goal:** Can we read the files and understand the API structure?
- [x] **Data Models:** Define `Endpoint`, `Method`, and `CollectionParser` traits in `src/models.rs`.
- [x] **Bruno Support:** Implement `parsers/bruno.rs` using `walkdir` and `regex` to extract URLs and logic from `.bru` files.
- [x] **Postman Support:** Implement `parsers/postman.rs` using `serde_json` to recursively parse Postman Collection v2.1 exports.
- [x] **OpenAPI Support:** Implement `parsers/openapi.rs` with full OpenAPI 3.0 support including:
  - [x] Local `$ref` resolution (`#/components/schemas/User`)
  - [x] External file `$ref` resolution (`./schemas/user.json#/definitions/User`)
  - [x] `oneOf`, `allOf`, `anyOf` schema composition
  - [x] Multiple content types (JSON, form-urlencoded, multipart, XML)
  - [x] Nested and array request bodies
  - [x] Server variable substitution
- [x] **CLI Interface:** Set up `clap` to handle arguments (`--input`, `--target`, `--token`).

## 🟡 Phase 2: The Engine (Async Execution) ✅ COMPLETED
**Goal:** Can we hit the API fast and safely?
- [x] **HTTP Client:** Configure `reqwest` with a shared connection pool for performance.
- [x] **Token Injection:** Create middleware/logic to inject `Authorization: Bearer <token>` headers into every request.
- [x] **Variable Substitution:** logic to replace `{{baseUrl}}` and param placeholders (`:id`, `{id}`) with actual test data.
- [x] **Concurrency:** Use `tokio::spawn` or `futures::stream::iter` to run checks in parallel (aim for 50+ concurrent requests).

## 🟠 Phase 3: The Logic (The "Switcheroo") ✅ COMPLETED
**Goal:** Can we actually find a vulnerability?
- [x] **Baseline Check:** Ensure the "Attacker Token" works for their *own* data first (sanity check).
- [x] **The Attack:** Implement the logic to force `Attacker Token` + `Victim ID` on all discovered GET endpoints.
- [x] **Verdict Engine:** Write the decision logic (`200 OK` vs `401/403`).
- [x] **Semantic Risk Scoring:** Logic-aware BOLA risk detection (0-100 score).

## 🔴 Phase 4: Integration (CI/CD & Reporting) ✅ COMPLETED
**Goal:** Make it useful for teams.
- [x] **Exit Codes:** Ensure the process exits with `1` if a vulnerability is confirmed.
- [x] **Pretty Printing:** Use the `colored` crate to make terminal output readable.
- [x] **CSV Export:** Generate CSV reports for vulnerability tracking.
- [x] **Markdown Export:** Generate Markdown reports for easy reading.
- [x] **GitHub Action:** Create reusable workflows for CI/CD and Releases.
- [x] **Multi-Platform Releases:** Auto-build for Linux, Windows, macOS.

## 🟣 CLI & User Experience ✅ COMPLETED
- [x] Design a simple, intuitive CLI with clear error messages and actionable output.
- [x] Add comprehensive command-line flags for customization.
- [x] **AI Integration:** Local Ollama support for PII detection.

---

## 🚀 Roadmap: v1.1.0 & Beyond

### High Priority
- [ ] **SARIF Export:** Generate `.sarif` JSON file so results appear in GitHub Security tabs.
- [ ] **Advanced Auth:** Support OAuth2, API keys, cookies (currently only Bearer tokens).
- [ ] **Replay Attacks:** Support importing real user sessions from browser HAR files.

### Medium Priority
- [ ] **Docker Image:** Publish `ghcr.io/abendrothj/doppel` container.
- [ ] **Advanced Fuzzing:** Inject SQLi (`' OR 1=1`), XSS, and negative integers.
- [ ] **Response Heuristics:** Better detection of "soft fails" (200 OK with error message body).

### Long Term / Stretch Goals
- [ ] **Web Dashboard:** A local UI to visualize scan results.
- [ ] **Custom Rules:** Allow users to define their own fuzzing rules via YAML.
