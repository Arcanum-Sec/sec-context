# Repository Guidelines

This repository is a content-first security reference. It ships two large Markdown guides plus a static landing page.

## Project Structure & Module Organization
- `ANTI_PATTERNS_BREADTH.md`: Broad catalog of 25+ AI code security anti-patterns with quick references.
- `ANTI_PATTERNS_DEPTH.md`: Deep-dive coverage of the 7 highest-priority vulnerabilities.
- `index.html`: Static landing page for the GitHub Pages site.
- `README.md`: Project overview, usage guidance, and source context.

## Build, Test, and Development Commands
There are no build or test scripts in this repository today.
- To preview changes, open `index.html` in a browser.
- To edit content, modify the Markdown files directly.

## Coding Style & Naming Conventions
- Markdown: keep headings short and scannable; use fenced code blocks for examples.
- HTML: keep changes minimal and readable; prefer semantic elements.
- Filenames follow `UPPER_SNAKE_CASE.md` for the large guides and conventional names for web assets.

## Testing Guidelines
No automated tests are configured. If you add tests or tooling, document the command(s) here and in `README.md`.

## Commit & Pull Request Guidelines
Recent history uses simple, descriptive summaries like `Update index.html` or `Update README.md`.
- Use short, direct commit messages that name the file or feature you changed.
- PRs should include a brief description of the change and, if relevant, a link to supporting sources or examples.

## Security & Content Integrity
- Do not include secrets or sensitive data in examples.
- Ensure any new anti-patterns include mitigation guidance and clear BAD/GOOD comparisons.
- If adding statistics, provide a credible source and keep wording precise.
