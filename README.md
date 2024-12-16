# Encode and Decode strings with Cryptography

[![Donate](https://img.shields.io/badge/Donate-PayPal-brightgreen.svg?style=plastic)](https://www.paypal.com/ncp/payment/6G9Z78QHUD4RJ)
[![License](https://img.shields.io/github/license/ddc/ddcCryptography.svg)](https://github.com/ddc/ddcCryptography/blob/master/LICENSE)
[![PyPi](https://img.shields.io/pypi/v/ddcCryptography.svg)](https://pypi.python.org/pypi/ddcCryptography)
[![PyPI Downloads](https://static.pepy.tech/badge/ddcCryptography)](https://pepy.tech/projects/ddcCryptography)
[![codecov](https://codecov.io/gh/ddc/ddcCryptography/graph/badge.svg?token=Q25ZT1URLS)](https://codecov.io/gh/ddc/ddcCryptography)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A//actions-badge.atrox.dev/ddc/ddcCryptography/badge?ref=main&label=build&logo=none)](https://actions-badge.atrox.dev/ddc/ddcCryptography/goto?ref=main)
[![Python](https://img.shields.io/pypi/pyversions/ddcCryptography.svg)](https://www.python.org)


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


# Run Tests and Get Coverage Report using Poe
```shell
poetry update --with test
poe tests
```


# License
Released under the [MIT License](LICENSE)



# Buy me a cup of coffee
+ [GitHub Sponsor](https://github.com/sponsors/ddc)
+ [ko-fi](https://ko-fi.com/ddcsta)
+ [Paypal](https://www.paypal.com/ncp/payment/6G9Z78QHUD4RJ)
