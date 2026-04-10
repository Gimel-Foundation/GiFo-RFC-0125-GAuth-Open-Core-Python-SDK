# Contributing to GAuth Open Core

Thank you for your interest in contributing to the GAuth Open Core SDK.

## Contribution Streams

GAuth SDK repositories accept contributions through two streams:

- **Community PRs (Stream A):** External developers submit pull requests targeting `main` on GitHub. These are reviewed and approved by the Gimel Foundation Board of Trustees for code quality, spec alignment, license compliance, and security.
- **Architecture team pushes (Stream B):** The Gimel architecture team pushes changes from the Replit development sandbox to the `replit` branch. These are merged to `main` via reviewed PR, with the same Board of Trustees review as Stream A.

Both streams merge to `main` through reviewed pull requests — no direct pushes to `main` are allowed. Neither stream automatically triggers a version bump or release. Only the architecture team decides when to cut a new version — version numbers are architectural decisions, not merge counters. See the SDK Implementation Guide §16 and the [Contribution and Release Policy](../docs/contribution-and-release-policy.md) for the full workflow.

## Development Setup

1. Clone the repository
2. Install dependencies: `pip install -e ".[dev]"`
3. Run tests: `pytest tests/ -v`

## Code Style

- Python 3.10+ with type annotations
- Pydantic v2 for data models
- No AI or probabilistic inference in the core SDK (Open Core is rule-based only)

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Add tests for new functionality
4. Ensure all tests pass (including conformance tests when available)
5. Update `CHANGELOG.md` under the `[Unreleased]` section (if the file exists)
6. Submit a pull request
7. The Gimel Foundation Board of Trustees will review your PR

## Adapter Development

If you are developing custom Type A or Type B adapters for the GAuth adapter system, see the adapter interfaces in `gauth_core/adapters/base.py`. Adapters must be registered through the `AdapterRegistry` with trust validation.

Type C adapter implementations (AI-Enabled Governance, Web3 Identity, DNA-Based Identities / PQC) are proprietary to the Gimel Foundation and are outside the scope of this open-source project. See `ADDITIONAL-TERMS.md` for details.

## Excluded Components and CLA

Contributions to the Open Core components are welcome and are licensed under the MPL 2.0 as stated in the `LICENSE` file.

Contributions that fall within the scope of the Excluded Components (Type C adapter implementations for slots 5, 6, and 7) require a separate Contributor License Agreement (CLA) with the Gimel Foundation. Contact info@gimelid.com for CLA inquiries.

## License

By contributing to the Open Core components of this project, you agree that your contributions will be licensed under the [Mozilla Public License 2.0](LICENSE).

See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md) for the three proprietary exclusions that are outside the scope of the MPL 2.0.
