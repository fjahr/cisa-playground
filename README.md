# cisa-playground

# Running the Full Aggregation Test

This project depends on the [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab) Python library for elliptic curve operations. Follow these steps to set up your environment and run the test:

## 1. Create and activate a Python virtual environment

From your project directory:

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
python fullagg.py
```

If everything is set up correctly, you should see:

```
Looks like it works!
```

## Troubleshooting
- Make sure you are using the virtual environment when running the script.
- If you encounter `ModuleNotFoundError: No module named 'secp256k1lab'`, ensure you have installed the dependency in the correct environment.

For more details, see the [secp256k1lab GitHub repository](https://github.com/secp256k1lab/secp256k1lab).
