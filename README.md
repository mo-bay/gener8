# base58
## Cryptocurrency key generation
### Private key, Public key, WIF, Address generator for cryptocurrencies.
Cryptocurrencies use a 256-bit random key which is converted in a WIF (Wallet Interchange Format key), where there is a 256-bit private key and a 512-bit public key. It uses Elliptic Curve Ciphers (ECC) to sign for transactions.

Can be used for generating (amongst other uses):
vAlertPubKey
ScriptPubKey
strSporkKey

![Imgur](https://i.imgur.com/nOzNsv9.png)
Edit base58.py

replace the hex code, <b>0x38</b> in this case, with your secret key decimal from base58Prefixes SECRET_KEY (chainparams) 
```return base58CheckEncode(0x38, key_hex.decode('hex'))```

Replace the symbol, <b>Z</b> in this case, with your address decimal from base58Prefixes PUBKEY_ADDRESS (chainparams)
```return 'Z' * leadingZeros + base58encode(base256decode(result))```

Install depencies: <br>
```sudo apt-get install python-setuptools```<br>
```sudo easy_install pip```<br>
```pip install ecdsa```

Generate keys: <br>
```python base58.py```
