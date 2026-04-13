# Gimel Foundation — Additional Terms and Exclusions

**Applies to:** GAuth Open Core  
**Base License:** Mozilla Public License 2.0 (MPL 2.0)  
**Copyright:** (c) 2024-2026 Gimel Foundation gGmbH i.G.

---

## Legal Framework — Dual-Layer Coexistence

GAuth Open Core is governed by a layered legal structure where multiple licenses **coexist** — they do not replace one another:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL 2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable (subject to compliance with MPL 2.0 and Gimel Foundation Additional Terms) |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (Auth-as-a-Service, Foundry, Wallet, managed infrastructure, Type C adapters) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

- **Gimel Foundation Legal Terms** apply to all use of GAuth, whether Open Core or proprietary.
- **Mozilla Public License 2.0 (MPL 2.0)** governs source code rights for Open Core components only.
- **Gimel Technologies Terms of Service** apply when a user opts into proprietary services, including the Excluded Components. The ToS applies **in addition to** MPL 2.0 — not as a replacement. SDK code and modifications to SDK files remain MPL 2.0 regardless.

### Coexistence Rule

You may run the SDK in pure Open Core mode (MPL 2.0 only, self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS applies in addition to MPL 2.0. Your SDK code and modifications to SDK files remain MPL 2.0 regardless.

### Downgrade Protection

If a hybrid customer later drops the proprietary platform, the ToS terminates but the MPL 2.0 license is not revoked. The customer keeps all SDK code and modifications, as long as acting in line with MPL 2.0 as well as the Legal Terms of Gimel Foundation. Violation of the Gimel Foundation Additional Terms (including unauthorized implementation of the Excluded Components listed below) terminates the MPL 2.0 license.

## Scope of the MPL 2.0 License

The Mozilla Public License, Version 2.0, applies to the Open Core components
of this project, including but not limited to:

- GAuth SDK source code (all languages)
- Policy Enforcement Point (PEP) evaluation engine
- Management API and client libraries
- Database schemas, validation schemas, and API specifications
- Governance profiles, ceiling tables, and validation pipelines
- Budget tracking, delegation chain management, and audit logging
- Type A and Type B adapter interfaces
- Type C adapter interfaces (method signatures only — not implementations)
- Ed25519 manifest verification code
- Conformance test suite

## Excluded Components — Proprietary License Required

The following functional domains are explicitly **excluded** from the scope of
the MPL 2.0 license — the MPL 2.0 does not apply to them. These Excluded
Components are outside the scope of the open-source license entirely and are
governed solely by the Gimel Technologies Terms of Service. Use of any Excluded
Component requires acceptance of the Gimel Technologies Terms of Service and
may not be used, reproduced, modified, or distributed without obtaining the
appropriate commercial license:

### 1. AI-Enabled Governance

Any modules, algorithms, models, or integrations that use artificial
intelligence or machine learning techniques to automate, augment, or inform
governance decisions, policy generation, risk scoring, anomaly detection, or
compliance assessment beyond the deterministic rule-based evaluation provided
by the Open Core PEP engine.

**Corresponding adapter:** Slot 5 (`ai_governance`) — `GovernanceAdapter` (Type C)

### 2. Web3 Integration

Any modules, smart contracts, adapters, or protocol bindings that enable
integration with blockchain networks, distributed ledger technologies (DLT),
decentralized identity (DID) systems, verifiable credentials on chain,
token-gated access control, or any other Web3-native functionality.

**Corresponding adapter:** Slot 6 (`web3_identity`) — `Web3IdentityAdapter` (Type C)

### 3. DNA-Based Identities and Post-Quantum Cryptography (PQC)

Any modules, cryptographic primitives, identity schemes, or protocol
extensions that implement or integrate:

  (a) Biometric identity systems based on DNA or genomic data;

  (b) Post-Quantum Cryptographic (PQC) algorithms, key encapsulation
      mechanisms, or digital signature schemes (including but not limited
      to CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, SPHINCS+, and any
      NIST PQC standardized or candidate algorithms);

  (c) Hybrid classical/post-quantum cryptographic schemes for mandate
      signing, credential issuance, or secure channel establishment.

**Corresponding adapter:** Slot 7 (`dna_identity`) — `DNAIdentityAdapter` (Type C)

## What This Means for Users

| Component | License | You May Modify | You May Redistribute |
|-----------|---------|----------------|----------------------|
| Open Core (SDK, PEP, Management API) | MPL 2.0 | Yes (file-level copyleft) | Yes |
| Type A/B adapter interfaces | MPL 2.0 | Yes | Yes |
| Conformance test suite | MPL 2.0 | Yes | Yes |
| Type C adapter implementations | Gimel Technologies ToS | No | No |

The Open Core is **fully functional** for production use without the Excluded
Components. AI-Enabled Governance adds an AI second-pass review; without it,
all evaluations are rule-based. Web3 and DNA identity extend the identity
model; without them, standard identity resolution is used.

## Notice to Contributors

By contributing to this project, you agree that your contributions to the
Open Core components are licensed under the MPL 2.0 as stated in the LICENSE
file. Contributions that fall within the scope of the Excluded Components
require a separate Contributor License Agreement (CLA) with the Gimel
Foundation.

## Contact

For proprietary licensing inquiries regarding Excluded Components:

  Gimel Foundation gGmbH i.G.  
  https://gimel.foundation  
  info@gimelid.com

For questions about the Open Core license:

  See https://mozilla.org/MPL/2.0/FAQ/
