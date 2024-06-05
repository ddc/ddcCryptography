# Few Utility Functions

[![License](https://img.shields.io/github/license/ddc/ddcCryptography.svg?style=plastic)](https://github.com/ddc/ddcCryptography/blob/master/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=plastic)](https://www.python.org)
[![PyPi](https://img.shields.io/pypi/v/ddcCryptography.svg?style=plastic)](https://pypi.python.org/pypi/ddcCryptography)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A//actions-badge.atrox.dev/ddc/ddcCryptography/badge?ref=main&style=plastic&label=build&logo=none)](https://actions-badge.atrox.dev/ddc/ddcCryptography/goto?ref=main)


# Install
```shell
pip install ddcCryptography
```

# Cryptography
```python
from ddcCryptography import Cryptography
cp = Cryptography()
```

+ GENERATE_PRIVATE_KEY
    + Generates a private key to be used instead of default one
    + But keep in mind that this private key will be needed to decode further strings
        ```
        @staticmethod
        generate_private_key() -> str
        ```

+ ENCODE
    + Encodes a given string
        ```
        encode(str_to_encode: str) -> str
         ```     

+ DECODE
    + Decodes a given string
        ```
        decode(str_to_decode: str) -> str
        ```


# Source Code
### Build
```shell
poetry build
```


### Run Tests
```shell
poe test
```


### Get Coverage Report
```shell
poe coverage
```


# License
Released under the [MIT License](LICENSE)
