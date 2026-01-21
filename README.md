# Sec-Context - AI Code Security Anti-Patterns for LLMs

**A comprehensive security reference distilled from 150+ sources to help LLMs generate safer code**

[Landing anmd github-pages website](https://arcanum-sec.github.io/sec-context/)

## The Problem

AI coding assistants are everywhere. **97% of developers** now use AI tools, and organizations report **40%+ of their codebase** is AI-generated. But there's a critical gap: AI models consistently reproduce the same dangerous security anti-patterns, with studies showing:

- **86% XSS failure rate** in AI-generated code
- **72% of Java AI code** contains vulnerabilities
- AI code is **2.74x more likely** to have XSS vulnerabilities than human-written code
- **81% of organizations** have shipped vulnerable AI-generated code to production

We built this guide to close that gap.

---

## What We Created

Two comprehensive security anti-pattern documents designed specifically for AI/LLM consumption:

### ANTI_PATTERNS_BREADTH.md (~65K tokens)
A complete reference covering **25+ security anti-patterns** with:
- Pseudocode BAD/GOOD examples for each pattern
- CWE references and severity ratings
- Quick-reference lookup table
- Concise mitigation strategies

### ANTI_PATTERNS_DEPTH.md (~100K tokens)
Deep-dive coverage of the **7 highest-priority vulnerabilities** with:
- Multiple code examples per pattern
- Detailed attack scenarios
- Edge cases frequently overlooked
- Complete mitigation strategies with trade-offs
- Why AI models generate these specific vulnerabilities

---

## The Top 10 AI Code Anti-Patterns

Based on our ranking matrix (Frequency × 2 + Severity × 2 + Detectability), these are the most critical patterns to watch for:

| Rank | Anti-Pattern | Priority Score | Key Statistic |
|------|--------------|----------------|---------------|
| 1 | **Dependency Risks (Slopsquatting)** | 24 | 5-21% of AI-suggested packages don't exist |
| 2 | **XSS Vulnerabilities** | 23 | 86% failure rate in AI code |
| 3 | **Hardcoded Secrets** | 23 | Scraped within minutes of exposure |
| 4 | **SQL Injection** | 22 | "Thousands of instances" in AI training data |
| 5 | **Authentication Failures** | 22 | 75.8% of devs wrongly trust AI auth code |
| 6 | **Missing Input Validation** | 21 | Root cause enabling all injection attacks |
| 7 | **Command Injection** | 21 | CVE-2025-53773 demonstrated real-world RCE |
| 8 | **Missing Rate Limiting** | 20 | Very high frequency, easy to detect |
| 9 | **Excessive Data Exposure** | 20 | APIs return full objects instead of DTOs |
| 10 | **Unrestricted File Upload** | 20 | Critical severity, enables RCE |

---

## How to Use These Files

### Important: These Are Large Files

- **Breadth version:** ~65,000 tokens
- **Depth version:** ~100,000 tokens

This is intentional. They're designed to be comprehensive references.

### Option 1: Large Context Window Models
If you're using a model with 128K+ context (Claude, GPT-4 Turbo, Gemini 1.5), you can include the entire breadth document in your system prompt or as a reference file.

### Option 2: Pieces for Smaller Contexts
Extract specific sections relevant to your task:
- Working on authentication? Pull the Authentication Failures section
- Building an API? Use the API Security and Input Validation sections
- Handling file uploads? Reference the File Handling section

### Option 3: Standalone Security Review Agent (Recommended)
The ideal use case: deploy a dedicated agent that reviews AI-generated code against these patterns. This agent:
- Takes code as input
- Checks against all 25+ anti-patterns
- Returns specific vulnerabilities found with remediation steps
- Works as a guardrail between AI code generation and production

### Option 4: Claude Code Security Review Skill (Recommended)
Deploy a dedicated skill in Claude Code that reviews AI-generated code against these patterns:
- Takes code as input (recent changes, specific files, or directories)
- Checks against all 25+ anti-patterns
- Returns specific vulnerabilities found with remediation steps
- Works as a guardrail between AI code generation and production

**Quick Install:**
```bash
mkdir -p .claude/skills .claude/security
curl -sL https://raw.githubusercontent.com/Arcanum-Sec/sec-context/main/.claude/skills/security-review.md -o .claude/skills/security-review.md
curl -sL https://raw.githubusercontent.com/Arcanum-Sec/sec-context/main/ANTI_PATTERNS_BREADTH.md -o .claude/security/ANTI_PATTERNS_BREADTH.md
curl -sL https://raw.githubusercontent.com/Arcanum-Sec/sec-context/main/ANTI_PATTERNS_DEPTH.md -o .claude/security/ANTI_PATTERNS_DEPTH.md
```

**Usage:**
```bash
/security-review                      # Quick review of recent changes (BREADTH)
/security-review path/to/file.ts      # Review specific file
/security-review --deep               # Deep audit using DEPTH document
/security-review --deep src/auth/     # Deep audit of auth code
```

| Mode | Document | Patterns | Best For |
|------|----------|----------|----------|
| Default | BREADTH | 25+ | General reviews, PRs |
| `--deep` | DEPTH | 7 critical | Auth, crypto, payments, pre-launch |

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────┐
│ AI Code Gen     │────>│ Security Review Skill │────>│ Reviewed    │
│ (Copilot, etc.) │     │ + Anti-Patterns Guide │     │ Code Output │
└─────────────────┘     └──────────────────────┘     └─────────────┘
```

---

## Research Sources

This guide synthesizes findings from **150+ individual sources** across 6 primary research categories:

### Primary Source Categories

| Source Type | Examples | Key Contributions |
|-------------|----------|-------------------|
| **CVE Databases** | NVD, MITRE CWE, Wiz | 40+ CVEs documented including IDEsaster collection |
| **Academic Research** | Stanford, ACM, arXiv, IEEE, USENIX | Empirical vulnerability rate studies |
| **Security Blogs** | Dark Reading, Veracode, Snyk, Checkmarx, OWASP | Industry reports and analysis |
| **Developer Forums** | HackerNews (17+ threads), Reddit (6 subreddits) | Real-world developer experiences |
| **Social Media** | Twitter/X security researchers | Real-time incident documentation |
| **GitHub** | Security advisories, academic studies | Large-scale code analysis |


---

## File Locations

```
├── ANTI_PATTERNS_BREADTH.md        # Full coverage, 25+ patterns
├── ANTI_PATTERNS_DEPTH.md          # Deep dive, 7 critical patterns
└── .claude/
    └── skills/
        └── security-review.md      # Claude Code skill definition
```

---

## Get Started

1. **Grab the files**
2. **Choose your approach** based on your context window and use case
3. **Integrate** into your AI coding workflow as system prompt, RAG reference, or review agent
4. **Generate safer code**

The goal isn't to replace human security review—it's to catch the obvious, well-documented anti-patterns that AI consistently reproduces, freeing up human reviewers for the subtle, context-dependent security decisions.

---

## Contributing

Found a pattern we missed? Have a better example? PRs are welcome =)

---

*Built by synthesizing 150+ sources across academic papers, CVE databases, security blogs, and developer communities. Because AI shouldn't keep making the same security mistakes.*
