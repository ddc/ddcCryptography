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


+ GENERATE_PRIVATE_KEY
    + Generates a private key to be used instead of default one
    + But keep in mind that this private key WILL BE NEEDED TO DECODE FURTHER STRINGS
    + Example of custom private key as "my_private_key" bellow

```python
from ddcCryptography import Cryptography
cp = Cryptography()
cp.generate_private_key()
```



+ ENCODE
    + Encodes a given string
```python
from ddcCryptography import Cryptography
str_to_encode = "test_str"
cp = Cryptography()
cp.encode(str_to_encode)
```

```python
from ddcCryptography import Cryptography
str_to_encode = "test_str"
cp = Cryptography("my_private_key")
cp.encode(str_to_encode)
```
 


+ DECODE
    + Decodes a given string
```python
from ddcCryptography import Cryptography
str_to_decode = "gAAAAABnSdKi5V81C_8FkM_I1rW_zTuyfnxCvvZPGFoAoHWwKzceue8NopSpWm-pDAp9pwAIW3xPbACuOz_6AhZOcjs3NM7miw=="
cp = Cryptography()
cp.decode(str_to_decode)
```

```python
from ddcCryptography import Cryptography
str_to_decode = "gAAAAABnSdKi5V81C_8FkM_I1rW_zTuyfnxCvvZPGFoAoHWwKzceue8NopSpWm-pDAp9pwAIW3xPbACuOz_6AhZOcjs3NM7miw=="
cp = Cryptography("my_private_key")
cp.decode(str_to_decode)
```



# Source Code
### Build
```shell
poetry build -f wheel
```


### Run Tests and Get Coverage Report
```shell
poetry run coverage run --omit=./tests/* --source=./ddcCryptography -m pytest -v && poetry run coverage report
```


# License
Released under the [MIT License](LICENSE)
