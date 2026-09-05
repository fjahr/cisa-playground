# Archived CISA drafts

Everything in this directory consists of earlier drafts and implementation code that were superseded by the actual BIPs:

- `halfagg/`: half-aggregation, superseded by [BIP 458](https://github.com/bitcoin/bips/pull/2205)
- `fullagg.py` and `bips/fullagg/`: full-aggregation, superseded by [BIP 459](https://github.com/bitcoin/bips/pull/2210)
- `bips/bip_taproot_keypath_markers.mediawiki` and `bips/bip_taproot_keypath_NO_markers.mediawiki`: CISA for Taproot key path spends, superseded by [BIP 460](https://github.com/bitcoin/bips/pull/2212)

# Running the Full Aggregation Test

This project depends on the [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab) Python library for elliptic curve operations. Follow these steps to set up your environment and run the test:

## 1. Create and activate a Python virtual environment

From the repository root:

```
python3 -m venv venv
```

- For bash/zsh:
  ```
  source venv/bin/activate
  ```
- For fish shell:
  ```
  source venv/bin/activate.fish
  ```

## 2. Install secp256k1lab into your virtual environment

```
pip install -r requirements.txt
```

## 3. Run the full aggregation test

```
python archive/fullagg.py
```

If everything is set up correctly, you should see:

```
Looks like it works!
```

## Troubleshooting
- Make sure you are using the virtual environment when running the script.
- If you encounter `ModuleNotFoundError: No module named 'secp256k1lab'`, ensure you have installed the dependency in the correct environment.

For more details, see the [secp256k1lab GitHub repository](https://github.com/secp256k1lab/secp256k1lab).
