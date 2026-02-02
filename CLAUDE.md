# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

This project uses a Python virtual environment located at `env_math/`.

```bash
# Activate the virtual environment
source env_math/bin/activate

# Install dependencies
pip install fido2 pytest
```

## Running the Application

```bash
source env_math/bin/activate
python fido2_demo.py
```

## Running Tests

```bash
source env_math/bin/activate
pytest test_fido2_demo.py -v
```

## Dependencies

- Python 3.12
- fido2 (python-fido2) - FIDO2/WebAuthn library
- pytest - Testing framework

## FIDO2 Demo Application

The `fido2_demo.py` is a complete shell-based FIDO2 demonstration that supports:

- **Registration**: Create credentials bound to a hardware security key (with optional discoverable/resident key support)
- **Authentication**: Verify identity by tapping the security key (with username)
- **Passwordless Login**: Authenticate using discoverable credentials (no username needed)
- **Multi-key Support**: Register multiple keys per user (backup keys)
- **PIN Management**: Set initial PIN, change PIN
- **Counter Validation**: Detect cloned credentials via signature counter

Credentials are stored locally in `fido2_credentials.json`.

Requires a FIDO2-compatible authenticator (YubiKey, SoloKey, etc.) connected via USB.

Note: Uses `localhost` as RP ID for local testing. Production deployments need actual domain and HTTPS.
