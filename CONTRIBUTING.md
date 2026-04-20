# Contributing to Virus.xcheck

Thanks for your interest in contributing. This guide covers the basics of getting set up and submitting changes.

## Setup

1. Fork and clone the repo
2. Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

3. Set up your API keys in a `.env` file (see README for details)

## Making Changes

1. Create a branch from `main` for your work
2. Keep changes focused and limited to one issue or feature per PR
3. Make sure the code parses cleanly: `python -c "import ast; ast.parse(open('virusxcheck.py').read())"`
4. Test your changes manually before submitting

## Pull Requests

- Open a PR against `main`
- Describe what you changed and why
- Link any related issues
- PRs require review before merging

## Style

- Keep it simple and readable
- Follow existing code patterns
- No unnecessary dependencies

## Reporting Issues

Open an issue on GitHub with a clear description of the problem or suggestion. For security issues see [SECURITY.md](SECURITY.md).
