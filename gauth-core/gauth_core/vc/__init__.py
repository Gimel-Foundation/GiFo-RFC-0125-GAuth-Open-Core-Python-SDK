"""W3C Verifiable Credentials translation layer — RFC 0116 §7 / Gap Spec G-07."""

from gauth_core.vc.serializer import poa_to_vc, vc_to_jwt_payload
from gauth_core.vc.did import resolve_did_web, resolve_did_key, create_did_key
from gauth_core.vc.status_list import BitstringStatusList
from gauth_core.vc.sd_jwt import create_sd_jwt, verify_sd_jwt_disclosures
from gauth_core.vc.openid import OpenID4VCIStub, OpenID4VPStub
