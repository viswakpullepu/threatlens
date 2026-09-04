# Get Shit Done (GSD) Workflow Guidelines

This workspace is powered by the **Get Shit Done (GSD)** development framework. Follow these core guidelines for context engineering, planning, and task execution.

## Core Philosophy: Spec-Driven Development
1. **Never code without a plan**: For any non-trivial change, always follow the sequence:
   **Research → Plan → Verify Plan → Execute → Verify Output → Ship**.
2. **Context Engineering**: Keep context clean and scoped. Never dump entire repositories into the prompt. Use targeted research and concise status tracking.
3. **Atomic Execution**: Break phases into clear, self-contained tasks with explicit verification steps.

## Project Memory Architecture (`.planning/`)
All project state and long-term memory are stored in the `.planning/` directory:
- `.planning/PROJECT.md`: Core project vision, architecture constraints, and key decisions.
- `.planning/ROADMAP.md`: Sequenced milestones and breakdown into phases.
- `.planning/STATE.md`: Active project status, current phase, blockers, next steps, and progress ledger. Always keep this updated!
- `.planning/REQUIREMENTS.md`: Concrete functional and non-functional requirements.
- `.planning/config.json`: Workflow preferences and model resolution settings.
- `.planning/phases/`: Phase artifacts (`XX-<phase-name>/PLAN.md`, `RESEARCH.md`, `VERIFICATION.md`, `SUMMARY.md`).

## Command Routing
When executing GSD workflows, use the specialized GSD skills available in this plugin:
- `/gsd-new-project`: Initialize a new project with structured interview, requirements, and roadmap.
- `/gsd-discuss-phase <N>`: Clarify requirements and gather domain context before planning phase N.
- `/gsd-plan-phase <N>`: Produce an executable `PLAN.md` for phase N with integrated plan checker verification.
- `/gsd-execute-phase <N>`: Execute phase tasks step-by-step with automated verification gates.
- `/gsd-verify-work <N>`: Test and validate completed deliverables against phase requirements.
- `/gsd-code-review`: Conduct a comprehensive review of code quality, test coverage, and security.
- `/gsd-quick`: Fast-track small, atomic fixes and tasks without full phase ceremonies.
- `/gsd-ship`: Prepare releases, updates, and changelogs.
- `/gsd-progress`: Check current progress and roadmap completion status.

## CLI and Runtime Tools
The plugin includes `gsd-tools` and the compiled GSD SDK:
- CLI utilities: `.agents/plugins/get-shit-done/get-shit-done/bin/gsd-tools.cjs`
- GSD SDK: `.agents/plugins/get-shit-done/sdk/dist/cli.js`
