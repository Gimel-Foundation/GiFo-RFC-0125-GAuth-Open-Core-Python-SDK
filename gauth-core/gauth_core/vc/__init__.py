"""W3C Verifiable Credentials translation layer — RFC 0116 §7 / Gap Spec G-07.

SDK Conformance Baseline
~~~~~~~~~~~~~~~~~~~~~~~~
This module provides the **Open Core conformance baseline** for W3C VC
Data Model v2.0.  Current scope:

- **Data Integrity Proofs**: Full ``ecdsa-rdfc-2019`` signing/verification
  when ``cryptography`` is installed and key material is supplied.  Without
  keys, a deterministic SHA-256 hash-integrity mode is available for
  offline/test scenarios (reported as ``mode='hash-integrity'``).
- **DID resolution**: ``did:web`` and ``did:key`` resolvers synthesise
  DID Documents from identifiers (no network fetch); suitable for
  SDK-level conformance and local validation.
- **Bitstring Status List**: v2.0 semantics with ``@context``
  ``https://www.w3.org/ns/credentials/v2`` (no legacy 2021 context).
  Revocation checks are local-object based (no remote fetch).
- **SD-JWT**: Selective disclosure with SHA-256 digests.  Claims are
  redacted from the issuer payload; verification is fail-closed.
- **OpenID4VCI**: Full credential issuance via pre-authorized code flow
  with nonce lifecycle management, real VC minting via poa_to_vc +
  ecdsa-rdfc-2019 Data Integrity Proofs.
- **OpenID4VP**: Presentation verification with Data Integrity Proof
  validation, Bitstring Status List revocation checks, and nonce binding.

Production deployments requiring full network DID resolution, remote
status list fetching, or HSM-backed key management should layer
additional adapters on top of these interfaces.
"""

from gauth_core.vc.serializer import poa_to_vc, vc_to_jwt_payload
from gauth_core.vc.did import resolve_did_web, resolve_did_key, create_did_key
from gauth_core.vc.status_list import BitstringStatusList
from gauth_core.vc.sd_jwt import create_sd_jwt, verify_sd_jwt_disclosures
from gauth_core.vc.openid import (
    OpenID4VCIssuer,
    OpenID4VPVerifier,
    OpenID4VCIStub,
    OpenID4VPStub,
    TrustedIssuerRegistry,
    create_verifiable_presentation,
)
