"""GAuth governance profiles — RFC 0115/0118 §9.2 ceiling tables."""

from gauth_core.profiles.ceilings import (
    CEILING_TABLE,
    CeilingDefinition,
    get_ceiling,
    get_profile_info,
    list_profiles,
    validate_against_ceiling,
)

__all__ = [
    "CEILING_TABLE",
    "CeilingDefinition",
    "get_ceiling",
    "get_profile_info",
    "list_profiles",
    "validate_against_ceiling",
]
