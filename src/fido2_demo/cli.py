#!/usr/bin/env python3
"""
FIDO2 Demo Application

A complete shell-based FIDO2 demo that demonstrates:
- Device detection
- Registration (credential creation) with multi-key support
- Authentication (assertion) with username
- Passwordless authentication (discoverable credentials)
- PIN management

Requires a FIDO2 compatible authenticator (e.g., YubiKey, SoloKey).

Note: Uses localhost as RP ID for local testing. Production deployments
need the actual domain and HTTPS origin.

To delete resident credentials from the key itself, use vendor tools:
- YubiKey: ykman fido credentials delete
- Other vendors: check manufacturer documentation
"""

import base64
import json
import sys
import secrets
from pathlib import Path

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AttestedCredentialData,
)

# Configuration
RP_ID = "localhost"
RP_NAME = "FIDO2 Demo Application"
CREDENTIALS_FILE = Path.cwd() / "fido2_credentials.json"
PIN_MAX_ATTEMPTS = 3  # Max attempts for wrong PIN before giving up


class CliInteraction(UserInteraction):
    """Handle user interaction prompts in the CLI."""

    def prompt_up(self):
        """Prompt for user presence (tap)."""
        print("\n" + "=" * 50)
        print("  >>> TAP YOUR SECURITY KEY NOW <<<")
        print("=" * 50 + "\n")

    def request_pin(self, permissions, rd_id):
        """Request PIN if device has PIN protection."""
        return input("Enter your FIDO2 PIN: ")

    def request_uv(self, permissions, rd_id):
        """Request user verification."""
        print("User verification required. Please verify on your device.")
        return True


def get_device():
    """Detect and return a FIDO2 device."""
    print("\nSearching for FIDO2 devices...")
    devices = list(CtapHidDevice.list_devices())

    if not devices:
        print("\nERROR: No FIDO2 device found!")
        print("Please insert your security key and try again.")
        return None

    if len(devices) == 1:
        print(f"Found device: {devices[0]}")
        return devices[0]

    print(f"\nFound {len(devices)} devices:")
    for i, dev in enumerate(devices):
        print(f"  [{i + 1}] {dev}")

    while True:
        try:
            choice = int(input("\nSelect device number: ")) - 1
            if 0 <= choice < len(devices):
                return devices[choice]
            print("Invalid selection.")
        except ValueError:
            print("Please enter a number.")


def load_credentials():
    """Load stored credentials from file.

    Storage format:
    {
        "username": {
            "user_id": "hex...",
            "display_name": "...",
            "credentials": [
                {
                    "attested_credential_data": "hex...",
                    "key_name": "My YubiKey",
                    "is_resident": true,
                    "counter": 0
                },
                ...
            ]
        }
    }
    """
    if CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE, "r") as f:
                data = json.load(f)
                # Convert stored data back to proper types
                for username, user_data in data.items():
                    user_data["user_id"] = bytes.fromhex(user_data["user_id"])
                    for cred in user_data["credentials"]:
                        cred["attested_credential_data"] = AttestedCredentialData(
                            bytes.fromhex(cred["attested_credential_data"])
                        )
                        # Handle old credentials without is_resident field
                        if "is_resident" not in cred:
                            cred["is_resident"] = False
                        # Handle old credentials without counter field
                        if "counter" not in cred:
                            cred["counter"] = 0
                return data
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Warning: Could not load credentials file: {e}")
            print("Starting with empty credentials.")
            return {}
    return {}


def save_credentials(credentials):
    """Save credentials to file."""
    data = {}
    for username, user_data in credentials.items():
        data[username] = {
            "user_id": user_data["user_id"].hex(),
            "display_name": user_data.get("display_name", username),
            "credentials": [
                {
                    "attested_credential_data": bytes(cred["attested_credential_data"]).hex(),
                    "key_name": cred["key_name"],
                    "is_resident": cred.get("is_resident", False),
                    "counter": cred.get("counter", 0),
                }
                for cred in user_data["credentials"]
            ]
        }

    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def check_resident_key_support(device):
    """Check if the device supports resident keys."""
    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(device)
        options = ctap2.info.options or {}
        return options.get("rk", False)
    except Exception:
        return False


def register_credential(client, server, device):
    """Register a new credential (create account or add backup key)."""
    print("\n" + "-" * 50)
    print("CREDENTIAL REGISTRATION")
    print("-" * 50)

    credentials = load_credentials()

    username = input("\nEnter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    # Check if user already exists
    is_new_user = username not in credentials

    if is_new_user:
        # New user - generate user ID
        user_id = secrets.token_bytes(32)
        display_name = input("Enter display name (or press Enter to use username): ").strip()
        if not display_name:
            display_name = username
        credentials[username] = {
            "user_id": user_id,
            "display_name": display_name,
            "credentials": []
        }
        print(f"\nCreating new account for: {username}")
    else:
        # Existing user - reuse user ID
        user_id = credentials[username]["user_id"]
        display_name = credentials[username].get("display_name", username)
        existing_count = len(credentials[username]["credentials"])
        print(f"\nUser '{username}' already has {existing_count} key(s) registered.")
        add_another = input("Add another key? (y/n): ").strip().lower()
        if add_another != 'y':
            print("Registration cancelled.")
            return
        print(f"\nAdding backup key for: {username}")

    # Get a name for this key
    key_name = input("Enter a name for this key (e.g., 'YubiKey 5', 'Backup'): ").strip()
    if not key_name:
        key_name = f"Key {len(credentials[username]['credentials']) + 1}"

    # Check for resident key support and ask user preference
    is_resident = False
    if check_resident_key_support(device):
        print("\nThis device supports discoverable credentials (resident keys).")
        print("Discoverable credentials allow passwordless login without typing username.")
        print("Note: Requires PIN/biometric and uses limited storage on the key.")
        make_resident = input("Make this a discoverable credential? (y/n): ").strip().lower()
        is_resident = make_resident == 'y'
    else:
        print("\nNote: This device does not support discoverable credentials.")

    # Create user entity
    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name=username,
        display_name=display_name,
    )

    # Build exclude list from ALL existing credentials for this user
    # This prevents registering the same physical key twice
    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=cred["attested_credential_data"].credential_id,
        )
        for cred in credentials[username]["credentials"]
    ]

    # Create registration options
    resident_key_req = ResidentKeyRequirement.REQUIRED if is_resident else ResidentKeyRequirement.DISCOURAGED
    user_verification = UserVerificationRequirement.REQUIRED if is_resident else UserVerificationRequirement.DISCOURAGED

    create_options, state = server.register_begin(
        user=user,
        credentials=exclude_credentials if exclude_credentials else None,
        resident_key_requirement=resident_key_req,
        user_verification=user_verification,
    )

    print("\nPlease wait for the prompt to tap your security key...")
    if is_resident:
        print("(You may need to enter your PIN)")

    try:
        # This will prompt for tap
        result = client.make_credential(create_options.public_key)

        # Complete registration
        auth_data = server.register_complete(state, result)

        # Store credential
        cred_data = auth_data.credential_data
        credentials[username]["credentials"].append({
            "attested_credential_data": cred_data,
            "key_name": key_name,
            "is_resident": is_resident,
            "counter": 0,  # Will be updated on first authentication
        })

        save_credentials(credentials)

        print("\n" + "=" * 50)
        print("  REGISTRATION SUCCESSFUL!")
        print("=" * 50)
        print(f"  Username: {username}")
        print(f"  Key Name: {key_name}")
        print(f"  Discoverable: {'Yes' if is_resident else 'No'}")
        print(f"  Total keys for user: {len(credentials[username]['credentials'])}")
        print(f"  Credential ID: {cred_data.credential_id.hex()[:32]}...")
        print("=" * 50)

    except Exception as e:
        # Clean up if this was a new user and registration failed
        if is_new_user and not credentials[username]["credentials"]:
            del credentials[username]
        print(f"\nRegistration failed: {e}")


def authenticate(client, server):
    """Authenticate with a registered credential (requires username)."""
    print("\n" + "-" * 50)
    print("AUTHENTICATION (with username)")
    print("-" * 50)

    credentials = load_credentials()

    if not credentials:
        print("\nNo registered credentials found.")
        print("Please register first using option 2.")
        return

    # Show registered users
    print("\nRegistered users:")
    for username, user_data in credentials.items():
        key_count = len(user_data["credentials"])
        print(f"  - {username} ({key_count} key{'s' if key_count != 1 else ''})")

    username = input("\nEnter username to authenticate: ").strip()

    if username not in credentials:
        print(f"User '{username}' not found.")
        return

    user_data = credentials[username]
    user_creds = user_data["credentials"]

    # Build allow_credentials from ALL credentials for this user
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=cred["attested_credential_data"].credential_id,
        )
        for cred in user_creds
    ]

    # Build list of AttestedCredentialData for verification
    attested_credentials = [
        cred["attested_credential_data"]
        for cred in user_creds
    ]

    # Create authentication options
    request_options, state = server.authenticate_begin(
        credentials=allow_credentials,
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )

    print(f"\nAuthenticating as: {username}")
    if len(user_creds) > 1:
        print(f"(Any of your {len(user_creds)} registered keys will work)")
    print("Please wait for the prompt to tap your security key...")

    try:
        # This will prompt for tap
        result = client.get_assertion(request_options.public_key)

        # Get assertions - usually one with allowCredentials, but handle multiple for consistency
        assertions = result.get_assertions()
        success = False
        last_error = None

        for idx, assertion in enumerate(assertions):
            # Get credential ID
            used_cred_id_raw = assertion.credential["id"]
            if isinstance(used_cred_id_raw, bytes):
                used_cred_id = used_cred_id_raw
            else:
                padded = used_cred_id_raw + "=" * (-len(used_cred_id_raw) % 4)
                used_cred_id = base64.urlsafe_b64decode(padded)

            # Find which key was used
            used_key_name = "Unknown"
            used_cred = None
            for cred in user_creds:
                if cred["attested_credential_data"].credential_id == used_cred_id:
                    used_key_name = cred["key_name"]
                    used_cred = cred
                    break

            if not used_cred:
                continue  # Try next assertion

            # Check counter BEFORE authenticate_complete (early clone detection)
            new_counter = assertion.auth_data.counter
            stored_counter = used_cred.get("counter", 0)

            if new_counter != 0 and new_counter <= stored_counter:
                print("\n" + "!" * 50)
                print("  SECURITY WARNING: POSSIBLE CLONED KEY!")
                print("!" * 50)
                print(f"  Counter did not increase (stored: {stored_counter}, received: {new_counter})")
                print("  This may indicate the credential was cloned.")
                print("!" * 50)
                return

            try:
                # Verify the assertion
                server.authenticate_complete(
                    state,
                    credentials=attested_credentials,
                    response=result.get_response(idx),
                )

                # Update counter after successful verification
                used_cred["counter"] = new_counter
                save_credentials(credentials)

                success = True
                print("\n" + "=" * 50)
                print("  AUTHENTICATION SUCCESSFUL!")
                print("=" * 50)
                print(f"  Welcome back, {username}!")
                print(f"  Authenticated with: {used_key_name}")
                print("=" * 50)
                break

            except Exception as e:
                last_error = e
                continue  # Try next assertion

        if not success and last_error:
            print(f"\nAuthentication failed: {last_error}")

    except Exception as e:
        print(f"\nAuthentication failed: {e}")


def passwordless_authenticate(client, server):
    """Authenticate using discoverable credentials (no username needed)."""
    print("\n" + "-" * 50)
    print("PASSWORDLESS AUTHENTICATION")
    print("-" * 50)
    print("\nThis uses discoverable credentials stored on your security key.")
    print("No username required - just tap your key.")
    print("(If multiple accounts are registered, your key may show a picker)")

    credentials = load_credentials()

    # Build a lookup from user_id to username and credentials
    user_id_to_data = {}
    for username, user_data in credentials.items():
        user_id_hex = user_data["user_id"].hex()
        user_id_to_data[user_id_hex] = {
            "username": username,
            "user_data": user_data,
        }

    # Create authentication options with NO credentials (discoverable mode)
    # User verification is required for discoverable credentials
    request_options, state = server.authenticate_begin(
        credentials=None,  # Empty = discoverable credential mode
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    print("\nPlease tap your security key (PIN/biometric may be required)...")

    try:
        # This will prompt for tap and PIN/UV
        result = client.get_assertion(request_options.public_key)

        # Get the assertions - may have multiple if several resident keys exist
        assertions = result.get_assertions()

        # Try each assertion until one succeeds (handles multiple resident creds)
        success = False
        last_error = None

        for idx, assertion in enumerate(assertions):
            # Get user handle (user_id) from the assertion
            user_handle = assertion.user.get("id") if assertion.user else None

            if not user_handle:
                continue  # Skip assertions without user info

            # Handle both bytes and base64-encoded user handle
            if isinstance(user_handle, bytes):
                user_id_bytes = user_handle
            else:
                padded = user_handle + "=" * (-len(user_handle) % 4)
                user_id_bytes = base64.urlsafe_b64decode(padded)

            user_id_hex = user_id_bytes.hex()

            # Look up user by user_id
            if user_id_hex not in user_id_to_data:
                continue  # Try next assertion

            matched_data = user_id_to_data[user_id_hex]
            username = matched_data["username"]
            user_data = matched_data["user_data"]

            # Find the matching credential for verification
            attested_credentials = [
                cred["attested_credential_data"]
                for cred in user_data["credentials"]
            ]

            # Get credential ID for key name lookup
            used_cred_id_raw = assertion.credential["id"]
            if isinstance(used_cred_id_raw, bytes):
                used_cred_id = used_cred_id_raw
            else:
                padded = used_cred_id_raw + "=" * (-len(used_cred_id_raw) % 4)
                used_cred_id = base64.urlsafe_b64decode(padded)

            # Find which key was used
            used_key_name = "Unknown"
            used_cred = None
            for cred in user_data["credentials"]:
                if cred["attested_credential_data"].credential_id == used_cred_id:
                    used_key_name = cred["key_name"]
                    used_cred = cred
                    break

            # Check counter BEFORE authenticate_complete (early clone detection)
            if used_cred:
                new_counter = assertion.auth_data.counter
                stored_counter = used_cred.get("counter", 0)

                if new_counter != 0 and new_counter <= stored_counter:
                    print("\n" + "!" * 50)
                    print("  SECURITY WARNING: POSSIBLE CLONED KEY!")
                    print("!" * 50)
                    print(f"  Counter did not increase (stored: {stored_counter}, received: {new_counter})")
                    print("  This may indicate the credential was cloned.")
                    print("!" * 50)
                    return

            try:
                # Verify the assertion
                server.authenticate_complete(
                    state,
                    credentials=attested_credentials,
                    response=result.get_response(idx),
                )

                # Update counter after successful verification
                if used_cred:
                    used_cred["counter"] = new_counter
                    save_credentials(credentials)

                success = True
                print("\n" + "=" * 50)
                print("  PASSWORDLESS AUTH SUCCESSFUL!")
                print("=" * 50)
                print(f"  Welcome back, {username}!")
                print(f"  Authenticated with: {used_key_name}")
                print("=" * 50)
                break

            except Exception as e:
                last_error = e
                continue  # Try next assertion

        if not success:
            if last_error:
                print(f"\nPasswordless authentication failed: {last_error}")
            else:
                print("\nError: No valid credentials found.")
                print("The credentials on your key don't match any registered user.")

    except Exception as e:
        error_msg = str(e)
        if "No credentials" in error_msg or "CTAP" in error_msg:
            print("\nNo discoverable credentials found on this key for this application.")
            print("Register a credential with 'discoverable' option enabled first.")
        else:
            print(f"\nPasswordless authentication failed: {e}")


def list_credentials():
    """List all registered credentials."""
    print("\n" + "-" * 50)
    print("REGISTERED CREDENTIALS")
    print("-" * 50)

    credentials = load_credentials()

    if not credentials:
        print("\nNo credentials registered yet.")
        return

    for username, user_data in credentials.items():
        key_count = len(user_data["credentials"])
        print(f"\n  User: {username}")
        print(f"  Display Name: {user_data.get('display_name', username)}")
        print(f"  User ID: {user_data['user_id'].hex()[:16]}...")
        print(f"  Registered Keys ({key_count}):")

        for i, cred in enumerate(user_data["credentials"], 1):
            attested = cred["attested_credential_data"]
            resident_status = "[Discoverable]" if cred.get("is_resident") else "[Server-side]"
            print(f"    [{i}] {cred['key_name']} {resident_status}")
            print(f"        Credential ID: {attested.credential_id.hex()[:24]}...")


def delete_credential():
    """Delete a registered credential or user."""
    print("\n" + "-" * 50)
    print("DELETE CREDENTIAL")
    print("-" * 50)

    credentials = load_credentials()

    if not credentials:
        print("\nNo credentials to delete.")
        return

    # Show registered users
    print("\nRegistered users:")
    for username, user_data in credentials.items():
        key_count = len(user_data["credentials"])
        print(f"  - {username} ({key_count} key{'s' if key_count != 1 else ''})")

    username = input("\nEnter username: ").strip()

    if username not in credentials:
        print(f"User '{username}' not found.")
        return

    user_data = credentials[username]
    user_creds = user_data["credentials"]

    if len(user_creds) == 1:
        # Only one key - confirm deletion of entire user
        print(f"\nThis is the only key for '{username}'.")
        print("WARNING: Deleting it will remove the user entirely!")
        if user_creds[0].get("is_resident"):
            print("NOTE: This won't remove the credential from your security key.")
            print("      Use your key's management tool to remove resident credentials.")
        confirm = input("Delete user and their only key? (yes/no): ").strip().lower()
        if confirm == "yes":
            del credentials[username]
            save_credentials(credentials)
            print(f"\nUser '{username}' deleted from server.")
        else:
            print("Deletion cancelled.")
    else:
        # Multiple keys - let user choose
        print(f"\nKeys for '{username}':")
        for i, cred in enumerate(user_creds, 1):
            resident_status = "[Discoverable]" if cred.get("is_resident") else "[Server-side]"
            print(f"  [{i}] {cred['key_name']} {resident_status}")
        print("  [A] Delete ALL keys (remove user)")

        choice = input("\nSelect key to delete: ").strip()

        if choice.upper() == 'A':
            confirm = input(f"Delete user '{username}' and ALL {len(user_creds)} keys? (yes/no): ").strip().lower()
            if confirm == "yes":
                del credentials[username]
                save_credentials(credentials)
                print(f"\nUser '{username}' and all keys deleted from server.")
            else:
                print("Deletion cancelled.")
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(user_creds):
                    key_name = user_creds[idx]["key_name"]
                    is_resident = user_creds[idx].get("is_resident")
                    del user_creds[idx]
                    save_credentials(credentials)
                    print(f"\nKey '{key_name}' deleted from server. User still has {len(user_creds)} key(s).")
                    if is_resident:
                        print("NOTE: The credential still exists on your security key.")
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid selection.")


def show_device_info(device):
    """Show information about the connected FIDO2 device."""
    print("\n" + "-" * 50)
    print("DEVICE INFORMATION")
    print("-" * 50)

    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(device)
        info = ctap2.info

        print(f"\n  Versions: {', '.join(info.versions)}")
        print(f"  AAGUID: {info.aaguid.hex()}")

        if info.extensions:
            print(f"  Extensions: {', '.join(info.extensions)}")

        options = info.options or {}
        rk_support = options.get("rk", False)
        print(f"  Resident Key Support: {rk_support}")
        if rk_support:
            print("    (Supports discoverable/passwordless credentials)")
        print(f"  User Verification: {options.get('uv', False)}")

        # Handle PIN status more carefully
        if "clientPin" in options:
            pin_set = options.get("clientPin")
            if pin_set is True:
                print("  PIN Status: Configured")
            elif pin_set is False:
                print("  PIN Status: Supported but not set")
            else:
                print(f"  PIN Status: {pin_set}")
        else:
            print("  PIN Status: Not supported")

        if info.max_cred_count_in_list:
            print(f"  Max credentials in list: {info.max_cred_count_in_list}")

    except Exception as e:
        print(f"\nCould not get device info: {e}")
        print("Device may only support CTAP1/U2F.")


def set_initial_pin(device):
    """Set the initial PIN on a new security key."""
    print("\n" + "-" * 50)
    print("SET INITIAL PIN")
    print("-" * 50)

    try:
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin
        from getpass import getpass

        ctap2 = Ctap2(device)
        info = ctap2.info

        # Check if device supports PIN
        options = info.options or {}
        if "clientPin" not in options:
            print("\nThis device does not support PIN protection.")
            return

        # Check if PIN is already set
        if options.get("clientPin") is True:
            print("\nWARNING: This device already has a PIN configured!")
            print("Use 'Change PIN' option instead if you want to change it.")
            return

        print("\nThis device has no PIN set. You can now set an initial PIN.")
        print("\nPIN Requirements:")
        print("  - Minimum 4 characters")
        print("  - Maximum 63 bytes (UTF-8 encoded)")

        # Get new PIN with confirmation
        while True:
            print()
            new_pin = getpass("Enter new PIN: ")

            if len(new_pin) < 4:
                print("PIN must be at least 4 characters. Try again.")
                continue

            if len(new_pin.encode('utf-8')) > 63:
                print("PIN is too long (max 63 bytes). Try again.")
                continue

            confirm_pin = getpass("Confirm new PIN: ")

            if new_pin != confirm_pin:
                print("PINs do not match. Try again.")
                continue

            break

        # Set the PIN
        client_pin = ClientPin(ctap2)
        client_pin.set_pin(new_pin)

        print("\n" + "=" * 50)
        print("  PIN SET SUCCESSFULLY!")
        print("=" * 50)
        print("  Your security key now requires this PIN.")
        print("  Keep it safe - you'll need it for operations.")
        print("=" * 50)

    except Exception as e:
        print(f"\nFailed to set PIN: {e}")


def change_pin(device):
    """Change the PIN on a security key."""
    print("\n" + "-" * 50)
    print("CHANGE PIN")
    print("-" * 50)

    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from getpass import getpass

    try:
        ctap2 = Ctap2(device)
        info = ctap2.info
    except Exception as e:
        print(f"\nCould not connect to device: {e}")
        return

    # Check if device supports PIN
    options = info.options or {}
    if "clientPin" not in options:
        print("\nThis device does not support PIN protection.")
        return

    # Check if PIN is set
    if options.get("clientPin") is not True:
        print("\nNo PIN is currently set on this device.")
        print("Use 'Set Initial PIN' option first.")
        return

    print("\nChanging PIN for this security key.")
    client_pin = ClientPin(ctap2)

    for attempt in range(PIN_MAX_ATTEMPTS):
        current_pin = getpass(f"Enter current PIN (attempt {attempt + 1}/{PIN_MAX_ATTEMPTS}): ")

        # Get new PIN with confirmation
        while True:
            print()
            new_pin = getpass("Enter new PIN: ")

            if len(new_pin) < 4:
                print("PIN must be at least 4 characters. Try again.")
                continue

            if len(new_pin.encode('utf-8')) > 63:
                print("PIN is too long (max 63 bytes). Try again.")
                continue

            if new_pin == current_pin:
                print("New PIN must be different from current PIN. Try again.")
                continue

            confirm_pin = getpass("Confirm new PIN: ")

            if new_pin != confirm_pin:
                print("PINs do not match. Try again.")
                continue

            break

        try:
            client_pin.change_pin(current_pin, new_pin)
            print("\n" + "=" * 50)
            print("  PIN CHANGED SUCCESSFULLY!")
            print("=" * 50)
            return

        except Exception as e:
            error_msg = str(e)
            if "PIN_INVALID" in error_msg:
                remaining = PIN_MAX_ATTEMPTS - attempt - 1
                if remaining > 0:
                    print(f"\nIncorrect PIN. {remaining} attempt(s) remaining.")
                else:
                    print("\nIncorrect PIN. No attempts remaining.")
            elif "PIN_AUTH_BLOCKED" in error_msg:
                print("\nError: PIN authentication blocked. Remove and reinsert key.")
                return
            elif "PIN_BLOCKED" in error_msg:
                print("\nError: PIN is blocked. Key must be reset (all data lost).")
                return
            else:
                print(f"\nFailed to change PIN: {e}")
                return

    print("\nToo many failed attempts. PIN change cancelled.")


def main_menu():
    """Display main menu and get user choice."""
    print("\n" + "=" * 50)
    print("       FIDO2 DEMO APPLICATION")
    print("=" * 50)
    print("\n  [1] Authenticate (with username)")
    print("  [2] Passwordless Login (discoverable)")
    print("  [3] Register (Create Account / Add Key)")
    print("  [4] List Registered Credentials")
    print("  [5] Delete Credential")
    print("  [6] Show Device Info")
    print("  [7] Set Initial PIN (new key)")
    print("  [8] Change PIN")
    print("  [9] Rescan for Devices")
    print("  [0] Exit")
    print("\n" + "-" * 50)

    return input("Select option: ").strip()


def main():
    """Main application entry point."""
    print("\n" + "#" * 50)
    print("#" + " " * 48 + "#")
    print("#      FIDO2 DEMO - Passwordless Auth Demo      #")
    print("#" + " " * 48 + "#")
    print("#" * 50)

    # Initial device detection
    device = get_device()

    if not device:
        print("\nPlease connect a FIDO2 device and restart the application.")
        sys.exit(1)

    # Create FIDO2 client and server
    rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
    server = Fido2Server(rp)

    origin = f"https://{RP_ID}"
    client_data_collector = DefaultClientDataCollector(origin)
    client = Fido2Client(device, client_data_collector, user_interaction=CliInteraction())

    print("\n>>> Device ready. Waiting for your input...")

    while True:
        choice = main_menu()

        if choice == "1":
            authenticate(client, server)
        elif choice == "2":
            passwordless_authenticate(client, server)
        elif choice == "3":
            register_credential(client, server, device)
        elif choice == "4":
            list_credentials()
        elif choice == "5":
            delete_credential()
        elif choice == "6":
            show_device_info(device)
        elif choice == "7":
            set_initial_pin(device)
        elif choice == "8":
            change_pin(device)
        elif choice == "9":
            new_device = get_device()
            if new_device:
                device = new_device
                client = Fido2Client(device, client_data_collector, user_interaction=CliInteraction())
                print("Device updated successfully.")
        elif choice == "0":
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
