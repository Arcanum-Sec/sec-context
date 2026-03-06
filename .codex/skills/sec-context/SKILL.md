---
name: sec-context
description: Use when generating or reviewing code for security risks (auth, input validation, DB queries, file handling, templates, secrets, SSRF/RCE). Applies the sec-context anti-patterns and outputs a checklist + concrete fixes + tests. Do not use for non-code or purely stylistic edits.
---

# sec-context skill

## Goal
Apply the sec-context anti-pattern guidance to code generation and code review so risky patterns are caught early and fixes are concrete.

## References (read these files when running the skill)
- references/ANTI_PATTERNS_BREADTH.md
- references/ANTI_PATTERNS_DEPTH.md

## When invoked, do this
1. Identify the risk surfaces in scope (e.g., auth/session, web endpoints, input parsing, DB access, file upload, command execution, templating, dependency choice, serialization).
2. Open `ANTI_PATTERNS_BREADTH.md` and shortlist the relevant anti-pattern checks for those surfaces.
3. For each shortlisted item, open `ANTI_PATTERNS_DEPTH.md` to confirm:
   - the exact failure mode
   - safe patterns/remediations
   - edge cases and common “almost fixed” traps
4. Produce outputs in this structure:

### A) Findings checklist
- For each relevant anti-pattern: PASS/FAIL and 1–2 lines why.

### B) Fixes
- For each FAIL: propose a specific code change (patch-quality guidance).
- Prefer allowlists, least privilege, safe defaults, and secure error handling/logging.
- Avoid “security theater”; focus on real exploit paths.

### C) Tests / verification
- Add or recommend tests that would fail before the fix and pass after (including negative cases).
- If applicable, add lint/static-analysis hooks.

## Guardrails
- Don’t paste long excerpts of the reference docs; summarize and apply.
- Don’t invent requirements; if key context is missing, ask targeted questions.
