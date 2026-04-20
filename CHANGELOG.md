# Changelog

## 0.2.2

- Move plotly, pandas, and jinja2 to optional `[report]` extra (#18)
- Base install reduced from ~110 MB to ~15 MB
- Add graceful import error for missing report dependencies
- Update README with PyPI install instructions, badges, and quick start

## 0.2.1

- Remove deprecated PDF reporter
- Remove stale CLI flags from README (-k, --vt-apikey)
- Update Python version requirement to 3.8+ in README

## 0.2.0

Maintenance update with security hardening and dependency cleanup.

- Remove API key CLI arguments to prevent shell history exposure
- Add strict SHA-256 hash input validation
- Restrict .env file permissions to owner-only on Unix
- Replace blanket warning suppression with targeted filter
- Fix all exit() calls to use sys.exit()
- Remove stdlib packages from requirements (pathlib, configparser)
- Remove unused reportlab dependency
- Add fpdf2 as optional dependency
- Pin all dependency versions
- Add pyproject.toml for pip installation
- Add CodeQL analysis workflow
- Add Dependabot for pip and GitHub Actions
- Add SECURITY.md
- Add CONTRIBUTING.md
- Enable secret scanning and push protection
- Deprecate PDF reporter (will be removed in a future version)
- Add test suite with 82 tests

## 0.1.0

Initial release.

- Hash lookup against Virus Exchange API with S3 bucket fallback
- VirusTotal v3 API enrichment
- CSV and JSON export
- Interactive HTML reports with Plotly charts
- Parallel hash processing
- Colorized terminal output
