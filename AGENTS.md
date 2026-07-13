# Agent instructions — SecureLogAnalyzer

Purpose: provide concise, actionable guidance for AI coding agents working on this codebase.

Quick Start
- **Python:** use a modern Python 3.11+ virtual environment.
- **Install deps:** `pip install -r requirements.txt` (see [requirements.txt](requirements.txt)).
- **Run app:** `python app.py` (the Flask app is in [app.py](app.py)).

Key files and directories
- **App entry:** [app.py](app.py)
- **Parser:** [parser/log_parser.py](parser/log_parser.py)
- **Analyzer:** [analyzer/threat_detector.py](analyzer/threat_detector.py)
- **Database models:** [models/database.py](models/database.py)
- **Web templates/static:** [templates/](templates/) and [static/](static/)
- **Tests:** [tests/](tests/) (run `pytest` if tests exist)
- **Docs:** [docs/](docs/) — link to design and diagrams
- **Logs/uploads:** [logs/](logs/) and [uploads/](uploads/)

Agent checklist (when making a change)
- **Read docs:** Check [README.md](README.md) and any files in [docs/](docs/) for context.
- **Run unit tests:** `pytest -q` (if tests exist) and ensure no regressions.
- **Smoke-run app:** start with `python app.py` and verify relevant endpoints.
- **Data effects:** Inspect [models/database.py](models/database.py) and `uploads/` before schema or migration changes.
- **Performance/safety:** For analyzer or parser changes, run sample logs in [sample_logs/](sample_logs/) to validate behavior.
- **Small, focused PRs:** Keep diffs minimal and include a test or reproduction case when possible.

What agents should *not* do automatically
- Create or run external network services, send data outside the repo, or perform destructive DB operations without explicit user approval.

Suggested follow-ups (optional)
- Add a `.github/copilot-instructions.md` or expand this file if you want repo-specific coding conventions or PR checklists.
- Add CI (GitHub Actions) to run tests and linting on PRs.

Contact / context
- This repository currently has an empty `README.md` and several placeholder modules. Inspect the files linked above before making behavioral changes.
