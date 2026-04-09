# Contributing to GAuth Open Core

Thank you for your interest in contributing to the GAuth Open Core SDK.

## Development Setup

1. Clone the repository
2. Install dependencies: `pip install -e ".[dev]"`
3. Run tests: `pytest tests/ -v`

## Code Style

- Python 3.10+ with type annotations
- Pydantic v2 for data models
- No AI or probabilistic inference in the core SDK

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Adapter Development

If you are developing proprietary adapters for the GAuth adapter system,
see the adapter interfaces in `gauth_core/adapters/base.py`. Adapters
must be registered through the `AdapterRegistry` with trust validation.

## License

By contributing, you agree that your contributions will be licensed
under the Apache License 2.0.
