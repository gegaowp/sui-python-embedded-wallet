# Sui Embedded Wallet Python Library

A simple Python library for generating Sui wallet addresses and deriving keys from mnemonics.

## Setup

1.  **Clone the repository (or ensure you have the project files):**
    ```bash
    # If using git
    git clone <your-repo-url>
    cd sui-embedded-wallet-py
    # Or just navigate to the directory containing main.py, test_wallet.py, requirements.txt
    cd /path/to/your/project
    ```

2.  **Create and Activate a Virtual Environment:**
    It's highly recommended to use a virtual environment.
    ```bash
    # Create the environment
    python3 -m venv .venv

    # Activate the environment
    # On macOS/Linux:
    source .venv/bin/activate
    # On Windows:
    # .venv\Scripts\activate
    ```
    Your terminal prompt should now start with `(.venv)`.

3.  **Install Dependencies:**
    ```bash
    python3 -m pip install -r requirements.txt
    ```

## Running the Code

Ensure your virtual environment is active (`source .venv/bin/activate`).

1.  **Run the main script:**
    This script demonstrates generating a new wallet and deriving keys from a specific test mnemonic.
    ```bash
    python3 main.py
    ```
    You should see output showing the generated details and the verified derived details.

2.  **Run the unit tests:**
    This verifies the key derivation logic against known values.
    ```bash
    python3 -m unittest test_wallet.py
    ```
    The tests should pass (`OK`).

## Deactivating the Environment

When you're done, you can deactivate the virtual environment:
```bash
deactivate
```

## Features
- Generate new wallet addresses with mnemonics
- Derive private keys from existing mnemonics
- Derive addresses from existing mnemonics

## Usage

### Generate a new wallet

```python
from main import Suiwallet

# Generate a new wallet with a random mnemonic
new_wallet = Suiwallet.generate_new_wallet()
print(f"Generated Mnemonic: {new_wallet.mnemonic}")

# Get the address and private key
address, private_key = new_wallet.derive_keys_from_mnemonic()
print(f"Sui Address: {address}")
print(f"Private Key: {private_key}")
```

### Recover wallet from mnemonic

```python
from main import Suiwallet

# Recover a wallet from an existing mnemonic
mnemonic = "border tiger theory iron early girl solid balance host pitch yard naive"
wallet = Suiwallet(mnemonic=mnemonic)

# Get the address and private key
address, private_key = wallet.derive_keys_from_mnemonic()
print(f"Recovered Sui Address: {address}")
print(f"Recovered Private Key: {private_key}")
```

### Get address only

```python
from main import Suiwallet

mnemonic = "border tiger theory iron early girl solid balance host pitch yard naive"
wallet = Suiwallet(mnemonic=mnemonic)

# Get just the address
address = wallet.derive_address_from_mnemonic()
print(f"Sui Address: {address}")
```

### Get private key only

```python
from main import Suiwallet

mnemonic = "border tiger theory iron early girl solid balance host pitch yard naive"
wallet = Suiwallet(mnemonic=mnemonic)

# Get just the private key
private_key = wallet.derive_pk_from_mnemonic()
print(f"Private Key: {private_key}")
```

## Dependencies

- pysui - Python SDK for Sui blockchain

## License

MIT 