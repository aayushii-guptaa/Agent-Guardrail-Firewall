
# 🛡️ Agent Guardrail Firewall
### Runtime Security and Policy Enforcement for AI Agents

**Agent Guardrail Firewall** is a Python-based prototype that evaluates AI-agent actions against a set of security policies before allowing simulated tool execution. It aims to reduce risks from prompt injection, unauthorized actions, sensitive-data exposure, and untrusted sources.

> **Project status:** Working prototype for demonstration and testing. Tool execution is simulated; live AI-agent integrations are not implemented.

---

## 🎯 Problem Statement

AI agents can interact with tools and process content from documents, websites, and other sources. Malicious instructions embedded in prompts or retrieved content can attempt to manipulate an agent into taking unsafe actions or exposing sensitive information.

Agent Guardrail Firewall demonstrates an additional policy-enforcement layer designed to inspect proposed actions and apply deterministic security checks.

## 💡 Our Solution

The prototype applies policy checks to each submitted action before deciding whether it should be:

- **ALLOWED** — the action passes the configured demo policies.
- **BLOCKED** — the action violates a security rule.
- **APPROVAL REQUIRED** — access to a sensitive resource requires human review.

The demo also includes outgoing-data checks, source-trust classification, security regression tests, and hash-linked audit events.

## ✨ Key Features

### 1. Runtime Action Policy Checks
- Allowlist for `read`, `search`, and `view` actions.
- Default-deny handling for unknown resources.
- Restrictions on sensitive resources.
- Policy decisions displayed with explanations.

### 2. Prompt-Injection Pattern Detection
- Detects selected suspicious instruction patterns.
- Includes English and Hindi/Hinglish examples.
- Blocks matching prompts before simulated tool execution.

### 3. Sensitive-Data Detection
- Detects Aadhaar-like and PAN-like patterns.
- Flags email/UPI-like identifiers and API secret/token patterns.
- Uses pattern matching and a Verhoeff checksum demonstration for Aadhaar-like test values.

### 4. Human Approval Workflow
- Holds requests for sensitive resources for review.
- Supports simulated approval and denial.
- Rechecks the request before approved simulated execution.

### 5. Outgoing-Data Security Checks
- Scans sample output for sensitive-data patterns.
- Checks for injection-like instructions in output.
- Applies an approved-recipient allowlist.

### 6. Explainable Audit Trail
- Records action, resource, source, risk level, status, and reason.
- Links audit events using SHA-256 hashes.
- Includes a hash-chain verification and tampering demonstration.
- Audit records are stored in session memory, not a persistent database.

### 7. Testing and Evaluation
- Automated security test suite.
- Outgoing-data regression tests.
- Illustrative baseline comparison dashboard.
- CSV exports for test results and audit logs.

---

## 🏗️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Security rules and application logic |
| Streamlit | Interactive web interface |
| Pandas | Test results, tables, and CSV exports |
| Regular Expressions | Pattern-based threat and sensitive-data detection |
| hashlib (SHA-256) | Hash-linked audit events |

## 🔄 How It Works

1. A user submits an action, resource, prompt, and source.
2. The policy layer checks for suspicious instructions and sensitive-data patterns.
3. The resource, source trust, and permitted action are evaluated.
4. The system allows, blocks, or holds the request for approval.
5. Allowed requests invoke a **simulated tool**.
6. Synthetic output is checked by the outgoing-data scanner.
7. The decision is recorded in the audit log.

## 🚀 Run Locally

### Prerequisites
- Python installed
- Git (optional, for repository management)

### Installation

Clone your repository or open the project folder, then run:

```bash
pip install -r requirements.txt
```

### Start the application

```bash
python -m streamlit run app.py
```

Streamlit will provide a local URL in the terminal. Open it in your browser.

## ☁️ Deployment

The application can be deployed as a Streamlit web service on a compatible hosting platform such as Render.

**Build command:**

```bash
pip install -r requirements.txt
```

**Start command:**

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port $PORT
```

Configure the service to use the Python environment supported by the hosting platform. Deployment is not complete until the hosted URL has been tested.

## 🧪 Testing

The prototype includes:
- Security tests for safe actions, unauthorized actions, prompt-injection patterns, sensitive-data patterns, and untrusted sources.
- Outgoing-data tests for sensitive patterns, unapproved recipients, and injection-like output.
- Approval workflow checks.
- Audit-chain integrity and tampering checks.

Run the test suites through the application interface and review the displayed results. Export the CSV reports as test evidence.

## ⚠️ Limitations and Security Considerations

- All tool actions are simulated. No real email, database, file system, payment, or external transmission is connected.
- Prompt-injection detection uses predefined patterns; it is not a complete semantic security classifier.
- Aadhaar/PAN and UPI/email-like detection is heuristic and does not establish official identity validity.
- Audit events are stored in session memory and are not persistent, tamper-proof storage.
- The baseline dashboard is illustrative, not an independently measured security benchmark.
- This prototype is not a security guarantee or a certification of compliance with India's DPDP Act.

## 🔭 Future Scope

- Integrate a real AI-agent framework through a controlled tool gateway.
- Add persistent audit storage and stronger access controls.
- Expand multilingual adversarial evaluation datasets.
- Measure false positives, prohibited-action pass-through, and latency.
- Add configurable policies and stronger threat detection.
- Evaluate against a measured baseline in a controlled test environment.

## 👥 Project

**Project:** Agent Guardrail Firewall  
**Team:** Infinity Pointers

Built as a hackathon prototype exploring action-level security controls for AI agents.

---

*Security decisions shown by this application apply to its configured demonstration environment.*
