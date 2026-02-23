# Contributing to SentinelForge

Thank you for your interest in contributing to SentinelForge! This document provides
guidelines for contributing to the project.

## Getting Started

1. **Fork the repository** and clone your fork
2. **Create a virtual environment**: `python -m venv .venv && source .venv/bin/activate`
3. **Install development dependencies**: `pip install -e ".[dev]"`
4. **Run the test suite**: `pytest`
5. **Create a branch** for your feature: `git checkout -b feature/your-feature-name`

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/sentinelforge.git
cd sentinelforge

# Set up development environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Verify everything works
pytest
sentinelforge demo
```

## Code Style

- Follow PEP 8 with a line length of 120 characters
- Use type hints for all function signatures
- Write docstrings for all public functions and classes
- Run `ruff check .` before submitting

## Testing

- Write tests for all new features
- Maintain test coverage above 80%
- Run the full test suite before submitting: `pytest --cov`
- Tests are in the `tests/` directory, mirroring `src/sentinelforge/` structure

## Pull Request Process

1. Update tests and documentation for your changes
2. Ensure all tests pass: `pytest`
3. Ensure code style passes: `ruff check .`
4. Write a clear PR description explaining what and why
5. Reference any related issues

## Adding Detection Rules

To add a new detection rule:

1. Add the rule to `BUILTIN_RULES` in `src/sentinelforge/models/detector.py`
2. Include a MITRE ATT&CK technique ID
3. Add a test case in `tests/test_models.py`
4. Update sample data if helpful for demonstration

## Adding Playbooks

To add a new response playbook:

1. Create a YAML file in `playbooks/`
2. Include `name`, `description`, `trigger_conditions`, and `steps`
3. Mark destructive actions with `requires_approval: true`
4. Add a test in `tests/test_playbook.py`

## Adding Log Parsers

To add support for a new log format:

1. Add a parser function in `src/sentinelforge/ingest/parsers.py`
2. Update `detect_format()` to recognize the new format
3. Add sample data in `sample_data/`
4. Add tests in `tests/test_parsers.py`

## Security

If you discover a security vulnerability, please report it privately to
corey@cwccie.com rather than opening a public issue. We take security seriously
and will respond promptly.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
