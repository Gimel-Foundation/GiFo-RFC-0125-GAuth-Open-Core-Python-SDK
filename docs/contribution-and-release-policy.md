# GAuth SDK — Contribution and Release Policy

**Version:** 1.0
**Date:** 2026-04-10
**Author:** Gimel Foundation Architecture Team
**Status:** Normative
**Companion to:** GAuth SDK Implementation Guide v1.3, §16

---

## 1. Purpose

This document defines the operational branch model, contribution workflow, and release process for all GAuth SDK repositories. It supplements the SDK Implementation Guide §16 (which defines the normative versioning and release rules) with the day-to-day workflow that the architecture team and community contributors follow.

The guide (§16) is the **what**. This document is the **how**.

---

## 2. Branch Model

```
main                ← protected release branch (all tags created here)
  ↑ PR (reviewed)
  │
replit              ← architecture team integration branch
  │                    (pushes from the Replit development sandbox land here)
  │
  ↑ PR (reviewed)
  │
feature/*           ← community feature branches (Stream A)
fix/*               ← community bugfix branches (Stream A)
```

### 2.1 Branch Definitions

| Branch | Purpose | Protection | Merge Path |
|--------|---------|------------|------------|
| `main` | Release branch. All release tags are created here. Represents the latest released or release-ready state. | Protected: no direct pushes, require PR review, require CI pass | Receives PRs from `replit` and from community feature/fix branches |
| `replit` | Architecture team integration branch. All pushes from the Replit development sandbox land here. | Protected: no direct pushes from outside Replit sandbox | Merges to `main` via reviewed PR |
| `feature/*`, `fix/*` | Short-lived community branches (Stream A) | None | Merge to `main` via reviewed PR |

### 2.2 Key Principles

1. **Every change enters `main` through a pull request.** No exceptions. This ensures full auditability in GitHub — every line of code has a PR with a diff, reviewer approvals, and timestamps.
2. **No long-lived `develop` or `release/*` branches.** The `main` branch is the single source of truth.
3. **The `replit` branch is not a second `main`.** It is an integration staging area for the architecture team. It accumulates work from the Replit sandbox and is periodically merged to `main` when the work is ready for review.
4. **Tags are only ever created on `main`.** Never on `replit` or feature branches.

---

## 3. Contribution Streams

### 3.1 Stream A — Community Pull Requests

**Flow:**

```
1. Contributor forks the repository
2. Contributor creates feature/* or fix/* branch from main
3. Contributor opens PR targeting main
4. CI runs conformance tests (CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S)
5. Board of Trustees reviews the PR
   - Code quality
   - Spec alignment (conformance tests)
   - License compliance (MPL 2.0, no Excluded Component code without CLA)
   - Security (no credential leaks, no unsafe crypto)
6. Board approves → PR merged to main
```

**Review authority:** Gimel Foundation Board of Trustees (pre-merge gate).

**Conformance test requirement:** All conformance tests MUST pass before the Board approves the merge.

### 3.2 Stream B — Architecture Team Pushes

**Flow:**

```
1. Architecture team works in the Replit development sandbox
2. Changes are pushed to the replit branch
3. When a batch of work is ready, a PR is opened from replit → main
4. CI runs conformance tests on the PR
5. Board of Trustees reviews the PR
   - Same review criteria as Stream A
6. Board approves → PR merged to main
```

**Review authority:** Gimel Foundation Board of Trustees (pre-merge gate, same as Stream A).

**Key difference from the previous model:** Stream B previously pushed directly to `main`. Under this policy, Stream B uses the same PR-based merge path as Stream A, ensuring identical auditability for both streams.

### 3.3 Merge Frequency

The architecture team decides when to open PRs from `replit` to `main`. This can be:

- **Per feature:** One PR per logical feature or fix
- **Batched:** Multiple related changes in a single PR with clear commit history
- **On demand:** Before a planned release

The Board of Trustees may request that large PRs be split for reviewability.

---

## 4. CI and Conformance Gates

Every PR targeting `main` — from either stream — triggers the full CI pipeline:

| Gate | Scope | Blocking? |
|------|-------|-----------|
| Conformance tests | CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S | Yes |
| Unit tests | Language-specific test suite | Yes |
| Linting | Language-specific style checks | Yes |
| License scan | Ensure no Excluded Component code in Open Core | Yes |
| Security scan | No credential leaks, no unsafe crypto | Yes |

**Branch protection rules on `main`:**

- Require PR reviews (minimum 1 Board member)
- Require status checks to pass (all CI gates)
- No direct pushes
- No force pushes
- No branch deletion

**Branch protection rules on `replit`:**

- Pushes allowed from Replit sandbox only
- No force pushes
- No branch deletion

---

## 5. Release Process

The release process is defined normatively in the SDK Implementation Guide §16.10. This section provides the operational workflow.

### 5.1 Release Decision

Only the architecture team decides when to release. Triggers include:

- Sufficient changes have accumulated since the last release
- A milestone is reached
- A critical fix must ship

### 5.2 Release Workflow

```
1. Architecture team decides a release is warranted
2. Ensure all pending replit → main PRs are merged
3. Create a release preparation branch from main:
   - Update CHANGELOG.md: [Unreleased] → [X.Y.Z] - YYYY-MM-DD
   - Bump version in package metadata
   - Update guide version compatibility constant (if needed)
4. Open PR for the release preparation branch → main
5. CI runs full conformance suite
6. Board of Trustees reviews the release PR
7. Board approves → PR merged to main
8. Create signed git tag on main: git tag -s vX.Y.Z
9. Publish package to registry
10. Create GitHub Release with CHANGELOG entry as release notes body
```

### 5.3 Post-Release

After a release:

- A fresh `[Unreleased]` section is added to `CHANGELOG.md` (can be done on `replit` and merged via the normal PR flow)
- The architecture team notifies SDK teams of the release
- If the release contains breaking changes, the migration guide is included in the GitHub Release notes

---

## 6. Auditability

This branch model provides the following audit guarantees:

| Audit Question | How It Is Answered |
|----------------|-------------------|
| Who wrote this code? | `git blame` on `main` → merge commit → PR → author |
| Who reviewed this code? | PR review approvals on GitHub |
| Did CI pass? | PR status checks on GitHub |
| What changed in this release? | `CHANGELOG.md` entry + GitHub Release notes |
| When was this code merged? | PR merge timestamp on GitHub |
| What is the full diff? | PR diff on GitHub |
| Was the Board involved? | PR review approvals show Board member(s) |

Every commit on `main` is traceable to a PR. Every PR has a CI record. Every release has a tag, a changelog entry, and a GitHub Release.

---

## 7. Excluded Components

Contributions to Excluded Components (Type C adapter implementations for slots 5, 6, and 7) require a separate Contributor License Agreement (CLA) with the Gimel Foundation, regardless of which stream the contribution comes through. See `ADDITIONAL-TERMS.md` for the three proprietary exclusions.

Contact: licensing@gimel.foundation

---

## 8. Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-10 | Architecture Team | Initial release. Defines dual-stream PR-based branch model with `replit` integration branch, CI gates, release workflow, and auditability guarantees. |

---

## 9. References

- GAuth SDK Implementation Guide v1.3, §16 — SDK Versioning & Release Policy (normative)
- GAuth SDK Implementation Guide v1.3, §15.7 — CONTRIBUTING.md Template Requirements
- [Semantic Versioning 2.0](https://semver.org)
- [Keep a Changelog](https://keepachangelog.com)
- [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)
- ADDITIONAL-TERMS.md — Gimel Foundation Additional Terms
