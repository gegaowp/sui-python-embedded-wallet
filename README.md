# Sui Embedded Wallet Python Library

A simple Python library for working with Sui blockchain wallets. This library provides methods for generating new wallet addresses, deriving private keys from mnemonics, and deriving addresses from mnemonics.

## Features
- Generate new wallet addresses with mnemonics
- Derive private keys from existing mnemonics
- Derive addresses from existing mnemonics

## Installation

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

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

## Running Tests

```bash
# Activate the virtual environment
source .venv/bin/activate

# Run the tests
python -m unittest test_wallet.py
```

## Dependencies

- pysui - Python SDK for Sui blockchain

## License

MIT 