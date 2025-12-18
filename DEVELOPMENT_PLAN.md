# 🗺️ Development Plan: Doppel

**Objective:** Build a high-performance, open-source security tool to detect BOLA/IDOR vulnerabilities in Fintech APIs.
**Target Release:** v1.0 (MVP)

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
- [x] **Verdict Engine:** Write the decision logic:
    - `200 OK` + JSON Body -> **VULNERABLE**
    - `401/403` -> **SECURE**
    - `404` -> **UNCERTAIN/SKIP**

## 🔴 Phase 4: Integration (CI/CD & Reporting) 🚧 IN PROGRESS
**Goal:** Make it useful for teams.
- [x] **Exit Codes:** Ensure the process exits with `1` if a vulnerability is confirmed.
- [x] **Pretty Printing:** Use the `colored` crate to make terminal output readable (Red for bugs, Green for safe).
- [x] **CSV Export:** Generate CSV reports for vulnerability tracking.
- [x] **Markdown Export:** Generate Markdown reports for easy reading.
- [ ] **SARIF Export:** Generate a standard `.sarif` JSON file so results appear in GitHub Security tabs.
- [ ] **GitHub Action:** Create a `action.yml` wrapper so users can drop this into their workflows easily.



## 🟣 CLI & User Experience ✅ COMPLETED
- [x] Design a simple, intuitive CLI with clear error messages and actionable output.
- [x] Add comprehensive command-line flags for customization.
- [ ] Consider a minimal web dashboard for visualizing results (stretch goal).

## 🟤 Real-World Data Support 🚧 IN PROGRESS
- [x] Support static token authentication (Bearer tokens).
- [ ] Support importing real authentication flows (OAuth, cookies, etc.), not just static tokens.
- [ ] Allow replaying real user sessions captured from browser/network tools.

## 🟢 Detection Intelligence ✅ COMPLETED
- [x] Analyze response bodies for sensitive data leaks, not just HTTP status codes.
- [x] Add heuristics for "soft fails" (e.g., error messages, partial data leaks).
- [x] Optional AI-powered PII detection using local Ollama.

## 🟠 Integration 🚧 IN PROGRESS
- [x] Output results in multiple formats (CSV, Markdown).
- [ ] Provide a Docker image and GitHub Action for easy CI/CD integration.
- [ ] Output results in SARIF format for GitHub Security integration.
- [ ] Output results in JSON and HTML formats.

## 🔵 Community & Adoption ✅ COMPLETED
- [x] Write clear documentation and provide sample collections.
- [x] Comprehensive README with examples and CI/CD integration guides.
- [ ] Add a "demo mode" with safe, public test APIs for new users.


## 🟤 Roadmap: Next Feature Support

- **Authentication Flows:**
    - [ ] Support OAuth2, API keys, cookies, and session-based authentication.
    - [ ] Allow scripting or recording login flows.

- **Advanced Parameter Handling:**
    - [ ] Detect and fuzz nested/complex parameters (JSON bodies, arrays, objects).
    - [ ] Support custom parameter rules and user-defined fuzzing strategies.

- **Mutational Fuzzing:**
    - [ ] Inject common attack payloads (SQLi, XSS, negative numbers, etc.) into parameters.
    - [ ] Try edge cases and invalid values.

- **Response Analysis:**
    - [ ] Add heuristics for soft fails (error messages, partial data leaks).
    - [ ] Support binary and file responses (not just JSON).

- **Reporting & Output:**
    - [ ] Export results in more formats (CSV, Markdown, PDF).
    - [ ] Generate detailed vulnerability reports with reproduction steps.

## 🔵 Phase 5: Future / Stretch Goals
- **Swagger/OpenAPI Support:** Add a parser for `openapi.json`.
- **Mutational Fuzzing:** Don't just swap IDs; try injecting SQL (`' OR 1=1`) or negative numbers into ID fields.
- **AI Analysis:** Use a small local LLM to analyze the JSON response to confirm if it looks like "Sensitive PII" (reducing false positives).
 - **AI Analysis:** Use a small local LLM (Ollama) to analyze the JSON response to confirm if it looks like "Sensitive PII" (reducing false positives). Default to local models to avoid sending sensitive responses to cloud providers.

## 🔧 LLM Configuration & Safety
- Default: use Ollama (local) for PII detection and analysis.
- Provide a config flag to toggle between `local` and `remote` analysis; remote should be disabled by default and require explicit opt-in.
- Log only analysis metadata (no raw response dumps) when using remote LLMs; redact sensitive fields before sending.

