"""
Tests for the Sui Embedded Wallet Library.

These tests verify key functionality:
- Deriving keys from a known mnemonic
- Matching expected addresses and private keys
"""

import unittest
from main import Suiwallet


class TestSuiWallet(unittest.TestCase):
    """Test suite for the Suiwallet class."""

    # Known test values
    TEST_MNEMONIC = "border tiger theory iron early girl solid balance host pitch yard naive"
    EXPECTED_ADDRESS = "0x0c0672024dabb73c864939acb971ac159fa14699cf4f12f9cd938f3c634d59df"
    EXPECTED_PK = "suiprivkey1qyavhj8evj29wqhjlfdz2uyf05vu4x5gnclkch35rm0j7hpkqjaqv0tlqrk"

    def setUp(self):
        """Set up test fixtures before each test."""
        self.wallet = Suiwallet(mnemonic=self.TEST_MNEMONIC)

    def test_derive_from_mnemonic(self):
        """Test deriving keys from a known mnemonic produces expected results."""
        # Test deriving both address and pk
        derived_address, derived_pk = self.wallet.derive_keys_from_mnemonic()
        
        self.assertEqual(
            derived_address, 
            self.EXPECTED_ADDRESS, 
            "Derived address should match expected"
        )
        self.assertEqual(
            derived_pk, 
            self.EXPECTED_PK, 
            "Derived private key should match expected"
        )

        # Test deriving address only
        derived_address_only = self.wallet.derive_address_from_mnemonic()
        self.assertEqual(
            derived_address_only, 
            self.EXPECTED_ADDRESS, 
            "Derived address (only) should match expected"
        )

        # Test deriving pk only
        derived_pk_only = self.wallet.derive_pk_from_mnemonic()
        self.assertEqual(
            derived_pk_only, 
            self.EXPECTED_PK, 
            "Derived private key (only) should match expected"
        )


if __name__ == '__main__':
    unittest.main() 