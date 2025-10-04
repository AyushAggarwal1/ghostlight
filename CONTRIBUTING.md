Contributing to Ghostlight
==========================

Thanks for your interest in contributing! This document outlines how to set up your environment, propose changes, and submit pull requests.

Getting Started
---------------

1. Fork the repository and clone your fork.
2. Use Python 3.9+.
3. Create and activate a virtual environment:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Project Layout
--------------

- CLI entrypoint: `ghostlight/cli.py` (exposed as `ghostlight` via `pyproject.toml`)
- Connectors and scanners live under `ghostlight/` and `readmes/` has docs per connector.
- Top-level usage docs are in `README.md`.

Development Workflow
--------------------

- Create a feature branch from `main`.
- Make focused commits with clear messages.
- Keep changes small and cohesive; separate unrelated changes into different PRs.

Running Locally
---------------

Common commands (see README for more examples):

```bash
# Activate venv
source .venv/bin/activate

# Show CLI help
ghostlight --help

# Example: scan a directory
ghostlight scan --scanner fs --target /path/to/dir --format table
```

Style, Linting, and Tests
-------------------------

This repo uses standard Python tooling. Please:

- Ensure code is readable and follows PEP 8 style guidelines.
- Add type hints where reasonable.
- Include docstrings for non-trivial functions/classes.
- Add or update tests when fixing bugs or adding features.

If you add new dependencies, update `requirements.txt` and keep versions pinned.

Documentation
-------------

- Update `README.md` and relevant files in `readmes/` when changing behavior or adding connectors.
- Include usage examples and flags for new scanners.

Pull Request Checklist
----------------------

Before opening a PR:

- The branch is up to date with `main` and rebased if necessary.
- Code builds and runs locally (basic sanity checks done with example commands).
- User-facing changes are documented.
- Large changes include a brief design note in the PR description.

How to Submit a PR
------------------

1. Push your branch to your fork.
2. Open a pull request against `AyushAggarwal1/ghostlight` `main`.
3. Fill out the PR template, describing the problem, solution, and testing.
4. Be responsive to review feedback; keep commits clean (consider squashing).

Code of Conduct
---------------

By participating, you agree to abide by our `CODE_OF_CONDUCT.md`.


