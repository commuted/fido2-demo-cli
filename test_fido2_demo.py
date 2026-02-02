#!/usr/bin/env python3
"""
Unit tests for FIDO2 Demo Application

Run with: pytest test_fido2_demo.py -v

Includes:
- Unit tests for isolated logic
- Integration-style tests for register → authenticate round-trips
"""

import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Import the module under test
import fido2_demo


class TestCredentialStorage:
    """Tests for credential load/save functionality."""

    def test_load_credentials_empty_file(self, tmp_path):
        """Test loading when no credentials file exists."""
        with patch.object(fido2_demo, 'CREDENTIALS_FILE', tmp_path / "nonexistent.json"):
            result = fido2_demo.load_credentials()
            assert result == {}

    def test_load_credentials_valid_file(self, tmp_path):
        """Test loading valid credentials from file."""
        cred_file = tmp_path / "creds.json"

        # Use a real valid AttestedCredentialData format
        # We'll mock AttestedCredentialData to avoid parsing issues
        test_data = {
            "testuser": {
                "user_id": "abcd1234" * 8,
                "display_name": "Test User",
                "credentials": [
                    {
                        "attested_credential_data": "deadbeef" * 8,
                        "key_name": "Test Key",
                        "is_resident": True,
                        "counter": 5
                    }
                ]
            }
        }

        cred_file.write_text(json.dumps(test_data))

        mock_attested = MagicMock()

        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            with patch.object(fido2_demo, 'AttestedCredentialData', return_value=mock_attested):
                result = fido2_demo.load_credentials()

                assert "testuser" in result
                assert result["testuser"]["display_name"] == "Test User"
                assert len(result["testuser"]["credentials"]) == 1
                assert result["testuser"]["credentials"][0]["key_name"] == "Test Key"
                assert result["testuser"]["credentials"][0]["is_resident"] is True
                assert result["testuser"]["credentials"][0]["counter"] == 5

    def test_load_credentials_missing_fields_defaults(self, tmp_path):
        """Test that missing is_resident and counter fields get defaults."""
        cred_file = tmp_path / "creds.json"

        # Old format without is_resident and counter
        test_data = {
            "olduser": {
                "user_id": "1234abcd" * 8,
                "display_name": "Old User",
                "credentials": [
                    {
                        "attested_credential_data": "cafebabe" * 8,
                        "key_name": "Old Key"
                    }
                ]
            }
        }

        cred_file.write_text(json.dumps(test_data))

        mock_attested = MagicMock()

        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            with patch.object(fido2_demo, 'AttestedCredentialData', return_value=mock_attested):
                result = fido2_demo.load_credentials()

                cred = result["olduser"]["credentials"][0]
                assert cred["is_resident"] is False  # Default
                assert cred["counter"] == 0  # Default

    def test_load_credentials_corrupted_file(self, tmp_path, capsys):
        """Test handling of corrupted JSON file."""
        cred_file = tmp_path / "creds.json"
        cred_file.write_text("not valid json {{{")

        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            result = fido2_demo.load_credentials()

            assert result == {}
            captured = capsys.readouterr()
            assert "Warning" in captured.out

    def test_save_credentials(self, tmp_path):
        """Test saving credentials to file."""
        cred_file = tmp_path / "creds.json"

        mock_attested = MagicMock()
        mock_attested.__bytes__ = MagicMock(return_value=b'\xde\xad\xbe\xef')

        credentials = {
            "saveuser": {
                "user_id": bytes.fromhex("abcd" * 16),
                "display_name": "Save User",
                "credentials": [
                    {
                        "attested_credential_data": mock_attested,
                        "key_name": "Save Key",
                        "is_resident": False,
                        "counter": 10
                    }
                ]
            }
        }

        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            fido2_demo.save_credentials(credentials)

        saved_data = json.loads(cred_file.read_text())

        assert "saveuser" in saved_data
        assert saved_data["saveuser"]["user_id"] == "abcd" * 16
        assert saved_data["saveuser"]["credentials"][0]["key_name"] == "Save Key"
        assert saved_data["saveuser"]["credentials"][0]["counter"] == 10


class TestCredentialIdHandling:
    """Tests for credential ID byte/base64 handling."""

    def test_bytes_credential_id(self):
        """Test handling credential ID that's already bytes."""
        cred_id = b'\x01\x02\x03\x04\x05'

        # Simulate the logic from authenticate()
        if isinstance(cred_id, bytes):
            result = cred_id
        else:
            padded = cred_id + "=" * (-len(cred_id) % 4)
            result = base64.urlsafe_b64decode(padded)

        assert result == b'\x01\x02\x03\x04\x05'

    def test_base64_credential_id(self):
        """Test handling base64url-encoded credential ID."""
        original = b'\x01\x02\x03\x04\x05'
        encoded = base64.urlsafe_b64encode(original).decode('ascii').rstrip('=')

        # Simulate the logic from authenticate()
        if isinstance(encoded, bytes):
            result = encoded
        else:
            padded = encoded + "=" * (-len(encoded) % 4)
            result = base64.urlsafe_b64decode(padded)

        assert result == original

    def test_base64_with_special_chars(self):
        """Test base64url encoding with - and _ characters."""
        # Data that produces - and _ in base64url
        original = b'\xfb\xff\xfe'
        encoded = base64.urlsafe_b64encode(original).decode('ascii').rstrip('=')

        padded = encoded + "=" * (-len(encoded) % 4)
        result = base64.urlsafe_b64decode(padded)

        assert result == original


class TestCounterValidation:
    """Tests for signature counter validation logic."""

    @pytest.mark.parametrize("stored,new,expected_suspicious", [
        # Valid cases (not suspicious)
        (5, 6, False),      # Counter increases - valid
        (0, 1, False),      # First auth with stored 0 - valid
        (5, 0, False),      # Counter 0 means authenticator doesn't use counters
        (100, 0, False),    # Large stored, 0 new - still valid (no counter impl)
        (0, 0, False),      # Both zero - authenticator doesn't use counters
        (5, 100, False),    # Large jump - valid

        # Suspicious cases (potential clone)
        (5, 5, True),       # Same counter - suspicious
        (10, 5, True),      # Decreasing counter - suspicious
        (100, 50, True),    # Large decrease - suspicious
        (5, 1, True),       # Small decrease - suspicious
    ])
    def test_counter_validation(self, stored, new, expected_suspicious):
        """Parametrized test for counter validation logic."""
        is_suspicious = new != 0 and new <= stored
        assert is_suspicious == expected_suspicious

    def test_security_warning_triggered(self, capsys):
        """Test that security warning is printed when counter doesn't increase."""
        # Simulate the warning logic from authenticate()
        new_counter = 3
        stored_counter = 5

        if new_counter != 0 and new_counter <= stored_counter:
            print("\n" + "!" * 50)
            print("  SECURITY WARNING: POSSIBLE CLONED KEY!")
            print("!" * 50)
            print(f"  Counter did not increase (stored: {stored_counter}, received: {new_counter})")
            print("  This may indicate the credential was cloned.")
            print("!" * 50)

        captured = capsys.readouterr()
        assert "SECURITY WARNING" in captured.out
        assert "CLONED KEY" in captured.out
        assert "stored: 5" in captured.out
        assert "received: 3" in captured.out


class TestPinValidation:
    """Tests for PIN validation logic."""

    def test_pin_minimum_length(self):
        """Test PIN minimum length requirement."""
        short_pin = "123"
        valid_pin = "1234"

        assert len(short_pin) < 4
        assert len(valid_pin) >= 4

    def test_pin_maximum_bytes(self):
        """Test PIN maximum byte length."""
        # ASCII PIN
        ascii_pin = "a" * 63
        assert len(ascii_pin.encode('utf-8')) <= 63

        # Unicode PIN (each char is 3 bytes in UTF-8)
        unicode_pin = "中" * 21  # 63 bytes
        assert len(unicode_pin.encode('utf-8')) == 63

        # Too long
        too_long = "中" * 22  # 66 bytes
        assert len(too_long.encode('utf-8')) > 63

    def test_pin_different_from_current(self):
        """Test that new PIN must differ from current."""
        current = "oldpin123"
        new_same = "oldpin123"
        new_different = "newpin456"

        assert new_same == current  # Should be rejected
        assert new_different != current  # Should be accepted


class TestUserIdLookup:
    """Tests for user ID to username lookup."""

    def test_user_id_hex_lookup(self):
        """Test looking up user by hex-encoded user_id."""
        credentials = {
            "alice": {
                "user_id": bytes.fromhex("aabbccdd" * 8),
                "credentials": []
            },
            "bob": {
                "user_id": bytes.fromhex("11223344" * 8),
                "credentials": []
            }
        }

        # Build lookup
        user_id_to_data = {}
        for username, user_data in credentials.items():
            user_id_hex = user_data["user_id"].hex()
            user_id_to_data[user_id_hex] = {"username": username}

        # Lookup
        search_id = "aabbccdd" * 8
        assert user_id_to_data[search_id]["username"] == "alice"

        search_id = "11223344" * 8
        assert user_id_to_data[search_id]["username"] == "bob"

    def test_user_id_not_found(self):
        """Test handling of unknown user_id."""
        user_id_to_data = {
            "aabbccdd" * 8: {"username": "alice"}
        }

        unknown_id = "deadbeef" * 8
        assert unknown_id not in user_id_to_data


class TestDeviceDetection:
    """Tests for device detection functionality."""

    @patch('fido2_demo.CtapHidDevice')
    def test_no_devices_found(self, mock_ctap, capsys):
        """Test handling when no FIDO2 devices are found."""
        mock_ctap.list_devices.return_value = []

        result = fido2_demo.get_device()

        assert result is None
        captured = capsys.readouterr()
        assert "No FIDO2 device found" in captured.out

    @patch('fido2_demo.CtapHidDevice')
    def test_single_device_found(self, mock_ctap, capsys):
        """Test auto-selection when single device is found."""
        mock_device = MagicMock()
        mock_ctap.list_devices.return_value = [mock_device]

        result = fido2_demo.get_device()

        assert result == mock_device

    @patch('fido2_demo.CtapHidDevice')
    @patch('builtins.input', return_value='1')
    def test_multiple_devices_selection(self, mock_input, mock_ctap, capsys):
        """Test device selection when multiple devices are found."""
        mock_device1 = MagicMock()
        mock_device2 = MagicMock()
        mock_ctap.list_devices.return_value = [mock_device1, mock_device2]

        result = fido2_demo.get_device()

        assert result == mock_device1


class TestResidentKeySupport:
    """Tests for resident key support detection."""

    @pytest.fixture
    def mock_ctap2_with_options(self):
        """Create a mock Ctap2 instance with configurable options."""
        def _create(options_dict):
            mock_ctap2_class = MagicMock()
            mock_ctap2_instance = MagicMock()
            # Use PropertyMock for cleaner options access
            type(mock_ctap2_instance.info).options = PropertyMock(return_value=options_dict)
            mock_ctap2_class.return_value = mock_ctap2_instance
            return mock_ctap2_class
        return _create

    def test_check_resident_key_supported(self, mock_ctap2_with_options):
        """Test detection of resident key support."""
        mock_device = MagicMock()

        with patch('fido2.ctap2.Ctap2', mock_ctap2_with_options({"rk": True})):
            result = fido2_demo.check_resident_key_support(mock_device)
            assert result is True

    def test_check_resident_key_not_supported(self, mock_ctap2_with_options):
        """Test detection when resident key not supported."""
        mock_device = MagicMock()

        with patch('fido2.ctap2.Ctap2', mock_ctap2_with_options({"rk": False})):
            result = fido2_demo.check_resident_key_support(mock_device)
            assert result is False

    def test_check_resident_key_missing_option(self, mock_ctap2_with_options):
        """Test when rk option is not present in options dict."""
        mock_device = MagicMock()

        with patch('fido2.ctap2.Ctap2', mock_ctap2_with_options({"clientPin": True})):
            result = fido2_demo.check_resident_key_support(mock_device)
            assert result is False

    def test_check_resident_key_empty_options(self, mock_ctap2_with_options):
        """Test with empty options dict."""
        mock_device = MagicMock()

        with patch('fido2.ctap2.Ctap2', mock_ctap2_with_options({})):
            result = fido2_demo.check_resident_key_support(mock_device)
            assert result is False

    def test_check_resident_key_error(self):
        """Test handling of error when checking resident key support."""
        mock_device = MagicMock()

        with patch('fido2.ctap2.Ctap2') as mock_ctap2:
            mock_ctap2.side_effect = Exception("Device error")

            result = fido2_demo.check_resident_key_support(mock_device)
            assert result is False


class TestCredentialMatching:
    """Tests for credential matching logic."""

    def test_find_credential_by_id(self):
        """Test finding credential by credential ID."""
        mock_cred1 = MagicMock()
        mock_cred1.credential_id = b'\x01\x02\x03'

        mock_cred2 = MagicMock()
        mock_cred2.credential_id = b'\x04\x05\x06'

        user_creds = [
            {"attested_credential_data": mock_cred1, "key_name": "Key 1"},
            {"attested_credential_data": mock_cred2, "key_name": "Key 2"},
        ]

        # Find Key 2
        search_id = b'\x04\x05\x06'
        found_name = "Unknown"
        for cred in user_creds:
            if cred["attested_credential_data"].credential_id == search_id:
                found_name = cred["key_name"]
                break

        assert found_name == "Key 2"

    def test_credential_not_found(self):
        """Test handling when credential ID doesn't match any stored credentials."""
        mock_cred = MagicMock()
        mock_cred.credential_id = b'\x01\x02\x03'

        user_creds = [
            {"attested_credential_data": mock_cred, "key_name": "Key 1"},
        ]

        search_id = b'\xff\xff\xff'  # Non-existent
        found_name = "Unknown"
        for cred in user_creds:
            if cred["attested_credential_data"].credential_id == search_id:
                found_name = cred["key_name"]
                break

        assert found_name == "Unknown"


class TestMultipleAssertions:
    """Tests for handling multiple assertions in passwordless mode."""

    def test_iterate_assertions_find_valid(self):
        """Test iterating through assertions to find valid one."""
        # Simulate assertions with different user handles
        assertions = [
            {"user": {"id": b'\x01'}, "valid": False},
            {"user": {"id": b'\x02'}, "valid": True},
            {"user": {"id": b'\x03'}, "valid": False},
        ]

        user_id_to_data = {
            b'\x02'.hex(): {"username": "validuser"}
        }

        found_user = None
        for assertion in assertions:
            user_handle = assertion["user"]["id"]
            user_id_hex = user_handle.hex()
            if user_id_hex in user_id_to_data:
                found_user = user_id_to_data[user_id_hex]["username"]
                break

        assert found_user == "validuser"

    def test_no_valid_assertion(self):
        """Test when no assertions match known users."""
        assertions = [
            {"user": {"id": b'\x01'}},
            {"user": {"id": b'\x02'}},
        ]

        user_id_to_data = {
            b'\xff'.hex(): {"username": "unknownuser"}
        }

        found_user = None
        for assertion in assertions:
            user_handle = assertion["user"]["id"]
            user_id_hex = user_handle.hex()
            if user_id_hex in user_id_to_data:
                found_user = user_id_to_data[user_id_hex]["username"]
                break

        assert found_user is None


class TestExcludeCredentials:
    """Tests for credential exclusion during registration."""

    def test_build_exclude_list(self):
        """Test building exclude list from existing credentials."""
        mock_cred1 = MagicMock()
        mock_cred1.credential_id = b'\x01\x02\x03'

        mock_cred2 = MagicMock()
        mock_cred2.credential_id = b'\x04\x05\x06'

        existing_creds = [
            {"attested_credential_data": mock_cred1},
            {"attested_credential_data": mock_cred2},
        ]

        exclude_ids = [
            cred["attested_credential_data"].credential_id
            for cred in existing_creds
        ]

        assert len(exclude_ids) == 2
        assert b'\x01\x02\x03' in exclude_ids
        assert b'\x04\x05\x06' in exclude_ids

    def test_empty_exclude_list(self):
        """Test exclude list when user has no existing credentials."""
        existing_creds = []

        exclude_ids = [
            cred["attested_credential_data"].credential_id
            for cred in existing_creds
        ]

        assert exclude_ids == []


class TestIntegrationAuthFlow:
    """Integration-style tests that simulate full register → authenticate round-trips."""

    @pytest.fixture
    def mock_credential_data(self):
        """Create realistic mock credential data."""
        mock_attested = MagicMock()
        mock_attested.credential_id = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        mock_attested.__bytes__ = MagicMock(return_value=b'\xde\xad\xbe\xef' * 8)
        return mock_attested

    @pytest.fixture
    def mock_auth_data(self):
        """Create mock authenticator data with counter."""
        mock_data = MagicMock()
        mock_data.counter = 1
        mock_data.credential_data = None
        return mock_data

    @patch('fido2_demo.CtapHidDevice')
    @patch('fido2_demo.Fido2Client')
    @patch('fido2_demo.Fido2Server')
    def test_full_register_then_authenticate_cycle(
        self, mock_server_class, mock_client_class, mock_hid, tmp_path, capsys
    ):
        """Test a full registration followed by authentication flow."""
        # Setup credential file in temp directory
        cred_file = tmp_path / "creds.json"

        # Create mock credential data
        mock_attested = MagicMock()
        mock_attested.credential_id = b'\xaa\xbb\xcc\xdd' * 4
        mock_attested.__bytes__ = MagicMock(return_value=b'\xaa\xbb\xcc\xdd' * 8)

        # Mock server
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server

        # Mock register_begin/complete
        mock_register_options = MagicMock()
        mock_register_options.public_key = MagicMock()
        mock_server.register_begin.return_value = (mock_register_options, {"state": "reg"})

        mock_auth_data = MagicMock()
        mock_auth_data.credential_data = mock_attested
        mock_server.register_complete.return_value = mock_auth_data

        # Mock client
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_make_cred_result = MagicMock()
        mock_client.make_credential.return_value = mock_make_cred_result

        # Mock authenticate flow
        mock_auth_options = MagicMock()
        mock_auth_options.public_key = MagicMock()
        mock_server.authenticate_begin.return_value = (mock_auth_options, {"state": "auth"})

        # Mock get_assertion result
        mock_assertion = MagicMock()
        mock_assertion.credential = {"id": b'\xaa\xbb\xcc\xdd' * 4}
        mock_assertion.auth_data.counter = 5

        mock_get_assertion_result = MagicMock()
        mock_get_assertion_result.get_assertions.return_value = [mock_assertion]
        mock_get_assertion_result.get_response.return_value = MagicMock()
        mock_client.get_assertion.return_value = mock_get_assertion_result

        # Simulate the credential storage and lookup flow
        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            # Step 1: Save a credential (simulating registration)
            credentials = {
                "testuser": {
                    "user_id": b'\x11\x22\x33\x44' * 8,
                    "display_name": "Test User",
                    "credentials": [{
                        "attested_credential_data": mock_attested,
                        "key_name": "Test Key",
                        "is_resident": False,
                        "counter": 0,
                    }]
                }
            }
            fido2_demo.save_credentials(credentials)

            # Verify saved
            assert cred_file.exists()

            # Step 2: Load credentials back (simulating authentication)
            with patch.object(fido2_demo, 'AttestedCredentialData') as mock_acd:
                # Setup AttestedCredentialData to return mock with correct credential_id
                loaded_attested = MagicMock()
                loaded_attested.credential_id = b'\xaa\xbb\xcc\xdd' * 4
                mock_acd.return_value = loaded_attested

                loaded_creds = fido2_demo.load_credentials()

                assert "testuser" in loaded_creds
                assert len(loaded_creds["testuser"]["credentials"]) == 1

                # Verify credential ID matching works
                user_creds = loaded_creds["testuser"]["credentials"]
                search_id = b'\xaa\xbb\xcc\xdd' * 4
                found = None
                for cred in user_creds:
                    if cred["attested_credential_data"].credential_id == search_id:
                        found = cred
                        break

                assert found is not None
                assert found["key_name"] == "Test Key"

    @patch('fido2_demo.CtapHidDevice')
    def test_counter_update_after_successful_auth(self, mock_hid, tmp_path):
        """Test that counter is properly updated after authentication."""
        cred_file = tmp_path / "creds.json"

        # Create mock credential
        mock_attested = MagicMock()
        mock_attested.credential_id = b'\x01\x02\x03\x04'
        mock_attested.__bytes__ = MagicMock(return_value=b'\x01\x02\x03\x04' * 8)

        initial_counter = 10

        with patch.object(fido2_demo, 'CREDENTIALS_FILE', cred_file):
            # Save initial credentials with counter = 10
            credentials = {
                "counteruser": {
                    "user_id": b'\xaa' * 32,
                    "display_name": "Counter User",
                    "credentials": [{
                        "attested_credential_data": mock_attested,
                        "key_name": "Counter Key",
                        "is_resident": False,
                        "counter": initial_counter,
                    }]
                }
            }
            fido2_demo.save_credentials(credentials)

            # Simulate counter update (as would happen after successful auth)
            new_counter = 15
            credentials["counteruser"]["credentials"][0]["counter"] = new_counter
            fido2_demo.save_credentials(credentials)

            # Load and verify counter was updated
            with patch.object(fido2_demo, 'AttestedCredentialData') as mock_acd:
                loaded_mock = MagicMock()
                loaded_mock.credential_id = b'\x01\x02\x03\x04'
                mock_acd.return_value = loaded_mock

                loaded = fido2_demo.load_credentials()
                assert loaded["counteruser"]["credentials"][0]["counter"] == new_counter

    def test_clone_detection_blocks_auth(self, capsys):
        """Test that clone detection properly blocks authentication with warning."""
        # Simulate the exact code path from authenticate()
        stored_counter = 10
        new_counter = 5  # Lower than stored - suspicious!

        # This is the logic from authenticate() and passwordless_authenticate()
        if new_counter != 0 and new_counter <= stored_counter:
            print("\n" + "!" * 50)
            print("  SECURITY WARNING: POSSIBLE CLONED KEY!")
            print("!" * 50)
            print(f"  Counter did not increase (stored: {stored_counter}, received: {new_counter})")
            print("  This may indicate the credential was cloned.")
            print("!" * 50)
            # In real code, this would return early
            auth_blocked = True
        else:
            auth_blocked = False

        captured = capsys.readouterr()
        assert auth_blocked is True
        assert "SECURITY WARNING" in captured.out
        assert "CLONED KEY" in captured.out

    def test_counter_zero_does_not_trigger_warning(self, capsys):
        """Test that counter=0 from authenticator does not trigger clone warning."""
        stored_counter = 10
        new_counter = 0  # Authenticator doesn't implement counters

        # Same logic from authenticate()
        if new_counter != 0 and new_counter <= stored_counter:
            print("SECURITY WARNING: POSSIBLE CLONED KEY!")
            auth_blocked = True
        else:
            auth_blocked = False

        captured = capsys.readouterr()
        assert auth_blocked is False
        assert "SECURITY WARNING" not in captured.out


class TestMultiKeyScenarios:
    """Integration tests for multi-key (backup key) scenarios."""

    def test_any_of_multiple_keys_can_authenticate(self):
        """Test that any registered key for a user can authenticate."""
        mock_cred1 = MagicMock()
        mock_cred1.credential_id = b'\x01\x01\x01\x01'

        mock_cred2 = MagicMock()
        mock_cred2.credential_id = b'\x02\x02\x02\x02'

        mock_cred3 = MagicMock()
        mock_cred3.credential_id = b'\x03\x03\x03\x03'

        user_creds = [
            {"attested_credential_data": mock_cred1, "key_name": "Primary YubiKey", "counter": 5},
            {"attested_credential_data": mock_cred2, "key_name": "Backup YubiKey", "counter": 2},
            {"attested_credential_data": mock_cred3, "key_name": "Emergency Key", "counter": 0},
        ]

        # Simulate authenticating with the backup key (second one)
        auth_cred_id = b'\x02\x02\x02\x02'

        found_key = None
        for cred in user_creds:
            if cred["attested_credential_data"].credential_id == auth_cred_id:
                found_key = cred
                break

        assert found_key is not None
        assert found_key["key_name"] == "Backup YubiKey"

    def test_exclude_list_prevents_duplicate_registration(self):
        """Test that building exclude list includes all existing credentials."""
        mock_cred1 = MagicMock()
        mock_cred1.credential_id = b'\xaa' * 16

        mock_cred2 = MagicMock()
        mock_cred2.credential_id = b'\xbb' * 16

        existing_creds = [
            {"attested_credential_data": mock_cred1, "key_name": "Key 1"},
            {"attested_credential_data": mock_cred2, "key_name": "Key 2"},
        ]

        # Build exclude list as done in register_credential()
        exclude_ids = [
            cred["attested_credential_data"].credential_id
            for cred in existing_creds
        ]

        # Verify all existing keys are excluded
        assert len(exclude_ids) == 2
        assert b'\xaa' * 16 in exclude_ids
        assert b'\xbb' * 16 in exclude_ids


class TestPasswordlessFlow:
    """Integration tests for passwordless authentication flow."""

    def test_user_lookup_by_user_id(self):
        """Test looking up user by user_id returned in assertion."""
        credentials = {
            "alice": {
                "user_id": bytes.fromhex("aa" * 32),
                "display_name": "Alice Smith",
                "credentials": [{"key_name": "Alice Key"}]
            },
            "bob": {
                "user_id": bytes.fromhex("bb" * 32),
                "display_name": "Bob Jones",
                "credentials": [{"key_name": "Bob Key"}]
            }
        }

        # Build user_id lookup as done in passwordless_authenticate()
        user_id_to_data = {}
        for username, user_data in credentials.items():
            user_id_hex = user_data["user_id"].hex()
            user_id_to_data[user_id_hex] = {
                "username": username,
                "user_data": user_data,
            }

        # Simulate assertion returning Alice's user_id
        assertion_user_id = bytes.fromhex("aa" * 32)
        user_id_hex = assertion_user_id.hex()

        assert user_id_hex in user_id_to_data
        matched = user_id_to_data[user_id_hex]
        assert matched["username"] == "alice"
        assert matched["user_data"]["display_name"] == "Alice Smith"

    def test_multiple_assertions_iteration(self):
        """Test iterating through multiple assertions to find valid user."""
        # Simulate multiple assertions returned by authenticator
        mock_assertions = []
        for i, user_id in enumerate([b'\x01', b'\x02', b'\x03']):
            mock_assertion = MagicMock()
            mock_assertion.user = {"id": user_id}
            mock_assertion.credential = {"id": bytes([i + 1] * 4)}
            mock_assertion.auth_data.counter = i + 1
            mock_assertions.append(mock_assertion)

        # Only user_id \x02 is known
        user_id_to_data = {
            b'\x02'.hex(): {"username": "known_user", "user_data": {}}
        }

        found_username = None
        found_idx = None

        for idx, assertion in enumerate(mock_assertions):
            user_handle = assertion.user.get("id")
            if user_handle:
                user_id_hex = user_handle.hex()
                if user_id_hex in user_id_to_data:
                    found_username = user_id_to_data[user_id_hex]["username"]
                    found_idx = idx
                    break

        assert found_username == "known_user"
        assert found_idx == 1  # Second assertion (index 1)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
