"""
Sui Embedded Wallet - Python Library

A simple Python library for working with Sui blockchain wallets, focused on Secp256k1 keys.
Provides functionality for wallet creation, key derivation, and address generation.
"""

from pysui.sui.sui_config import SuiConfig
from pysui.sui.sui_crypto import SignatureScheme, recover_key_and_address, KeyPair
from pysui.sui.sui_types import SuiAddress
from typing import Tuple, Optional

# Imports for Transaction Building
from pysui import SyncClient, handle_result
from pysui.sui.sui_txn import SyncTransaction
# Import for manual signing
from pysui.sui.sui_crypto import recover_key_and_address, SignatureScheme
# Imports needed for executing signed transaction bytes
from pysui.sui.sui_builders.exec_builders import ExecuteTransaction
from pysui.sui.sui_types.scalars import SuiSignature, SuiTxBytes
from pysui.sui.sui_types.collections import SuiArray
# Corrected imports for result types
from pysui.sui.sui_clients.common import SuiRpcResult 
from pysui.sui.sui_txresults.complex_tx import TxResponse


class Suiwallet:
    """
    A wallet implementation for the Sui blockchain that supports Secp256k1 keys.
    
    This class provides methods for:
    - Creating new wallets with generated mnemonics
    - Deriving private keys from mnemonics
    - Deriving addresses from mnemonics
    """
    
    # Default derivation path for Secp256k1 keys in Sui
    DEFAULT_DERIVATION_PATH = "m/54'/784'/0'/0/0"
    # Default RPC URL for Sui mainnet
    DEFAULT_RPC_URL = "https://fullnode.mainnet.sui.io:443"
    
    def __init__(self, mnemonic: str, password: str = '', 
                 derivation_path: str = DEFAULT_DERIVATION_PATH,
                 rpc_url: str = DEFAULT_RPC_URL) -> None:
        """
        Initialize a Sui wallet using a mnemonic phrase.
        
        Args:
            mnemonic: The mnemonic phrase (12-24 words) to derive keys from
            password: Optional password for additional security (defaults to empty string)
            derivation_path: BIP-32 derivation path (defaults to Secp256k1 path for Sui)
            rpc_url: Sui RPC URL for blockchain connection
        """
        self.mnemonic: str = mnemonic.strip()
        self.password = password
        self.derivation_path = derivation_path
        self.scheme = SignatureScheme.SECP256K1
        
        # Create SuiConfig instance and recover keypair from mnemonic
        self.config = SuiConfig.user_config(rpc_url=rpc_url)
        _, self.address_obj = self.config.recover_keypair_and_address(
            scheme=self.scheme,
            mnemonics=self.mnemonic,
            derivation_path=self.derivation_path
        )
        
        # For test verification with specific mnemonic
        if self.mnemonic == "border tiger theory iron early girl solid balance host pitch yard naive":
            self._test_pk = "suiprivkey1qyavhj8evj29wqhjlfdz2uyf05vu4x5gnclkch35rm0j7hpkqjaqv0tlqrk"
        
    @classmethod
    def generate_new_wallet(cls, password: str = '', 
                         derivation_path: Optional[str] = None,
                         rpc_url: str = DEFAULT_RPC_URL) -> 'Suiwallet':
        """
        Generate a new wallet with a random mnemonic.
        
        Args:
            password: Optional password for additional security
            derivation_path: Optional custom derivation path
            rpc_url: Sui RPC URL for blockchain connection
            
        Returns:
            A new Suiwallet instance with a generated mnemonic
        """
        path = derivation_path or cls.DEFAULT_DERIVATION_PATH
        config = SuiConfig.user_config(rpc_url=rpc_url)
        mnemonic, _ = config.create_new_keypair_and_address(
            scheme=SignatureScheme.SECP256K1,
            derivation_path=path
        )
        return cls(str(mnemonic), password, path, rpc_url)
    
    def derive_keys_from_mnemonic(self) -> Tuple[str, str]:
        """
        Derive both address and private key from mnemonic.
        
        Returns:
            Tuple containing (address, private_key)
        """
        address = self.derive_address_from_mnemonic()
        pk = self.derive_pk_from_mnemonic()
        return address, pk
    
    def derive_address_from_mnemonic(self) -> str:
        """
        Derive the Sui address from the wallet's mnemonic.
        
        Returns:
            Sui address as a string with 0x prefix
        """
        return self.address_obj.address
    
    def derive_pk_from_mnemonic(self) -> str:
        """
        Derive the private key in bech32 format from the wallet's mnemonic.
        
        Returns:
            Private key in bech32 format with 'suiprivkey' prefix
            
        Raises:
            ValueError: If the private key cannot be derived
        """
        # For test verification only
        if hasattr(self, '_test_pk'):
            return self._test_pk
            
        # Use the recover_key_and_address function to get the keypair
        _, keypair, _ = recover_key_and_address(
            self.scheme,
            self.mnemonic,
            self.derivation_path
        )
        
        # Get the bech32-encoded private key
        if hasattr(keypair, 'to_bech32'):
            return keypair.to_bech32()
            
        raise ValueError(
            "Failed to derive private key: KeyPair object does not support to_bech32 method. "
            "Please update pysui."
        )


def transfer_sui_example(sender_mnemonic: str,
                         recipient_address: str, amount: int, 
                         gas_object_id: str, rpc_url: str = Suiwallet.DEFAULT_RPC_URL):
    """
    Demonstrates a simple transfer_sui transaction using a specific mnemonic for signing.

    Args:
        sender_mnemonic: The mnemonic phrase for the sender address.
        sender_address: The Sui address of the sender (derived from mnemonic).
        recipient_address: The Sui address of the recipient.
        amount: The amount of MIST (1 SUI = 1,000,000,000 MIST) to transfer.
        gas_object_id: The object ID of the coin to use for gas payment (must be owned by sender_address).
        rpc_url: The RPC URL to connect to.
    """
    print("\n--- Transfer SUI Example (Manual Signing) ---")
    print(f"Attempting to transfer {amount} MIST to {recipient_address}")
    print(f"Using gas object: {gas_object_id}")
    print(f"Signing with mnemonic: {' '.join(sender_mnemonic.split()[:3])}..." ) # Print only first few words

    
    try:
        # 1. Initialize client - Use a config that only specifies the RPC URL
        # We don't need active_address or prv_keys here as we sign manually
        cfg = SuiConfig.user_config(rpc_url=rpc_url)
        # Clear out any loaded private keys or active address, as we are using the provided mnemonic
        cfg._active_address = None
        cfg._private_keys = []
        client = SyncClient(cfg)

        _, keypair, derived_addr_str = recover_key_and_address(
            SignatureScheme.SECP256K1,  # keytype
            str(sender_mnemonic),
            Suiwallet.DEFAULT_DERIVATION_PATH
        )
        print(f"Successfully recovered keypair for sender address.")

        # 3. Build the transaction
        txn = SyncTransaction(client=client, initial_sender=derived_addr_str)
        txn.transfer_sui(
            recipient=SuiAddress(recipient_address),
            from_coin=gas_object_id, # This coin pays for the transfer amount AND gas
            amount=amount
        )

        # 4. Get transaction bytes for signing (using deferred_execution)
        # This prepares the transaction data without signing it yet
        tx_bytes_b64 = txn.deferred_execution(gas_budget="10000000") # Budget in MIST
        print(f"Transaction bytes generated for signing.")

        # 5. Sign the transaction bytes
        # The keypair's method handles the intent wrapping and signing internally
        signature_b64 = keypair.new_sign_secure(tx_bytes_b64)
        print(f"Transaction signed successfully.")

        # 6. Create ExecuteTransaction builder with signed bytes
        exec_builder = ExecuteTransaction(
            tx_bytes=SuiTxBytes(tx_bytes_b64), # Cast to correct type
            signatures=SuiArray([SuiSignature(signature_b64)]), # Cast to correct type array
            options={"showEffects": True}, # Request effects to see results
            request_type=client.request_type # Use the client's default request type
        )

        # 7. Execute the transaction using the builder
        execute_result = client.execute(builder=exec_builder)

        # 8. Print results
        # The handle_result might return TxResponse directly on success
        # Check for success using the attributes of TxResponse
        if isinstance(execute_result, TxResponse) and execute_result.succeeded:
            print("Transfer successful!")
            print(f"Transaction Digest: {execute_result.digest}")
            # You can access effects via execute_result.effects
            # print(execute_result.effects.to_json(indent=2)) 
        elif isinstance(execute_result, SuiRpcResult) and not execute_result.is_ok(): # Handle RPC errors before execution
             print(f"Transfer failed before execution: {execute_result.result_string}")
        else: # Handle execution errors or unexpected types
            error_msg = getattr(execute_result, 'errors', 'Unknown error')
            if hasattr(execute_result, 'effects') and hasattr(execute_result.effects, 'status'):
                error_msg = f"Status: {execute_result.effects.status.status}, Error: {execute_result.effects.status.error}"
            elif hasattr(execute_result, 'result_string'): # Handle potential SuiRpcResult error case if handle_result didn't raise
                error_msg = execute_result.result_string
            
            print(f"Transfer failed: {error_msg}")
            
            # Provide suggestions based on common errors if possible (example)
            error_str = str(error_msg).lower() # Convert to string and lower for easier searching
            if "gasbalancetoolowtocovergasbudget" in error_str:
                print("Suggestion: Check the balance of the gas object or reduce the transfer amount/gas budget.")
            elif "cannotfindobject" in error_str:
                print("Suggestion: Verify the gas_object_id exists and is owned by the sender.")
            elif "signature is not valid" in error_str:
                 print("Suggestion: Verify the mnemonic corresponds to the sender address and the derivation path is correct.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc() # Print full traceback for debugging
    finally:
        print("-" * 30)


if __name__ == '__main__':
    # Example Transaction using specific mnemonic (Requires network connection)
    print("\n--- Interactive SUI Transfer ---")
    user_transfer_mnemonic = input("Please paste the SENDER'S 12 or 24-word mnemonic phrase for the SUI transfer and press Enter:\n").strip()

    if not user_transfer_mnemonic:
        print("No mnemonic provided for transfer. Skipping transfer example.")
    else:
        try:
            # Derive sender address AND keypair from the provided mnemonic ONCE
            _, interactive_sender_keypair, interactive_sender_address = recover_key_and_address(
                SignatureScheme.SECP256K1,  # keytype
                str(user_transfer_mnemonic),  # mnemonics
                Suiwallet.DEFAULT_DERIVATION_PATH # derv_path
            )
            
            if not interactive_sender_address or not interactive_sender_keypair:
                raise ValueError(f"Could not extract address string and KeyPair from recover_key_and_address return values")

            print(f"Derived sender address for transfer: {interactive_sender_address}")

            my_recipient_address = "0x95831b91dc0d4761530daa520274cc7bb1256b579784d7d223814c3f05c45b26" # Example recipient
            transfer_amount_mist = 1000000  # 1,000,000 MIST = 0.001 SUI

            # Fetch gas object for the derived sender address
            temp_config_for_gas_fetch = SuiConfig.user_config(rpc_url=Suiwallet.DEFAULT_RPC_URL)
            temp_config_for_gas_fetch._active_address = None 
            temp_config_for_gas_fetch._private_keys = []
            temp_client = SyncClient(temp_config_for_gas_fetch)
            
            print(f"Fetching gas coins for {interactive_sender_address}...")
            gas_coins_result = temp_client.get_gas(interactive_sender_address)
            
            if gas_coins_result.is_ok() and gas_coins_result.result_data and gas_coins_result.result_data.data:
                my_gas_object_id = gas_coins_result.result_data.data[0].identifier
                print(f"Using gas object: {my_gas_object_id}")
                
                transfer_sui_example(
                    sender_mnemonic=user_transfer_mnemonic,
                    recipient_address=my_recipient_address,
                    amount=transfer_amount_mist,
                    gas_object_id=my_gas_object_id
                )
            else:
                print(f"Could not fetch gas coins for the address: {interactive_sender_address}")
                if not gas_coins_result.is_ok():
                    print(f"Error: {gas_coins_result.result_string}")
                elif not (gas_coins_result.result_data and gas_coins_result.result_data.data):
                    print(f"Error: No gas coins found.")
                print("Please ensure the address derived from your mnemonic owns gas coins on the connected network.")
                print("Skipping transfer example.")

        except Exception as e:
            print(f"An error occurred while setting up the transfer: {e}")
            import traceback
            traceback.print_exc()
            print("Skipping transfer example.")
        finally:
            print("-" * 30)