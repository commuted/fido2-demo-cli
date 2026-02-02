"""
FIDO2 Demo CLI - A complete shell-based FIDO2/WebAuthn demo application.
"""

__version__ = "0.1.0"

from .cli import (
    main,
    get_device,
    load_credentials,
    save_credentials,
    check_resident_key_support,
    RP_ID,
    RP_NAME,
    CREDENTIALS_FILE,
    PIN_MAX_ATTEMPTS,
)

__all__ = [
    "main",
    "get_device",
    "load_credentials",
    "save_credentials",
    "check_resident_key_support",
    "RP_ID",
    "RP_NAME",
    "CREDENTIALS_FILE",
    "PIN_MAX_ATTEMPTS",
]
