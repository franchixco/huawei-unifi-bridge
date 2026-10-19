# Contributing

Contributions are welcome, whether written with or without AI assistance.
Read [README.md](README.md) for supported behavior and limitations, and
[AGENTS.md](AGENTS.md) for the project's safety and implementation constraints.
Keep public documentation, contribution descriptions and pull requests in English.

## Before making changes

- Discuss substantial features, new dependencies, new device support or changes
  to router write access with a maintainer before implementation.
- Keep each contribution focused on one problem. Avoid unrelated formatting,
  refactoring or generated-file changes.
- Describe the problem and expected behavior. For bugs, provide reproducible
  steps and relevant versions using sanitized or synthetic data.
- Preserve upstream attribution and license notices. Identify the source of any
  copied or adapted material; do not present third-party work as original work.

## Required AI disclosure

**Every contribution and PR must explicitly state whether AI was used: Yes or
No.** This applies to code, tests, documentation, translations, design/review
suggestions incorporated into the work, and contribution/PR descriptions.

AI use includes generative autocomplete, chat assistants and coding agents whose
output or advice influenced the submitted contribution. Ordinary deterministic
formatters and linters alone do not count as AI assistance.

Include this declaration in each PR and in other substantive submissions, such
as contributed code snippets, documentation or technical proposals in issues:

```text
AI assistance: Yes / No (choose one)
Tools/models: Name the tools; include the model if known, or N/A if No.
Scope: Explain which files, sections or activities were AI-assisted, or N/A if No.
Review and verification: Explain your review, actual checks and remaining gaps.
```

- **Yes:** identify the tools and summarize their role. Distinguish generated
  content from material you subsequently changed or verified. Exact percentages
  or model versions are not required when unknown.
- **No:** explicitly write `AI assistance: No`; do not leave the declaration
  blank or assume that silence means no AI was used.
- If AI involvement in material you are submitting is uncertain, explain that
  uncertainty and resolve the declaration with a maintainer before merge. Do
  not claim `No` without a basis.
- Update the declaration if AI is used during revisions or to prepare the PR.
- Do not include private prompts, conversation exports, credentials or customer
  information as evidence. A concise, sanitized summary is sufficient.

AI assistance is not a reason by itself to accept or reject a contribution.
The same correctness, safety, attribution and review requirements apply to all
work. Contributors must understand and review the complete submitted diff and
remain responsible for it; naming an AI tool does not transfer responsibility.
Maintainers may request corrections, supporting evidence or a smaller change.

The project's own AI involvement is disclosed in the
[README](README.md#ai-development-disclosure). That disclosure does not replace
the declaration required for each new contribution.

## Development and verification

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
uv run --no-project --python .venv/bin/python make test
```

- Add regression coverage for bug fixes and tests for non-trivial new behavior.
- Update README, configuration examples and affected callers when behavior or
  operational requirements change.
- Include the commands you actually ran and their results. Disclose skipped or
  blocked checks and why; never describe a partial suite as a full pass.
- Documentation-only changes may use relevant link, example and consistency
  checks instead of running the application test suite; state what was checked.
- Separate synthetic/local tests from hardware and controller validation. Report
  versions and limitations, not deployment-specific addresses or identifiers.
- Do not test by disrupting someone else's Wi-Fi. Hardware access is not
  required for every contribution, but untested hardware claims must be explicit.

## Safety and privacy

- Keep `.env`, adoption keys, cookies, Wi-Fi passwords, state and volume backups
  out of commits, PRs, issues, AI prompts and public logs.
- Use generic placeholders and synthetic fixtures. Do not publish raw ACS/WLAN
  responses, HAR files or captures containing client information.
- Do not erase volumes, reset identities, forget/readopt devices or change a
  physical router without the deployment owner's explicit permission.
- Preserve observation-only defaults, allowlisted writes, baseline protection,
  writable-field checks and fresh readback confirmation.
- Do not fabricate client generations, traffic, signal or missing telemetry.
- Do not submit unsupported UniFi controls as if they work on Huawei hardware.

## Pull request requirements

Use the [PR template](.github/pull_request_template.md). Each PR must include:

1. The problem, intended outcome and relevant issue references, if any.
2. A focused summary of the change and what is deliberately out of scope.
3. A completed **Yes/No AI disclosure**, with scope and review details.
4. Actual verification evidence and any checks not performed.
5. Compatibility, security, configuration and persistent-state impact, including
   a safe rollback/update approach when applicable.
6. Updated tests/docs and preserved third-party attribution where relevant.

Keep incomplete or unverified work in draft. A PR needs at least one maintainer
approval before merge, and required corrections must be addressed. Request a new
review after material changes to an already reviewed diff. Missing or incomplete
AI disclosure must be corrected before merge.

These are contribution and review policies, not a claim that branch protection
or automated disclosure checks have been configured. Repository administrators
must configure any desired hosting-platform enforcement separately.
