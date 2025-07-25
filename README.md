# Encode and Decode strings with Cryptography

[![Donate](https://img.shields.io/badge/Donate-PayPal-brightgreen.svg?style=plastic)](https://www.paypal.com/ncp/payment/6G9Z78QHUD4RJ)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPi](https://img.shields.io/pypi/v/ddcCryptography.svg)](https://pypi.python.org/pypi/ddcCryptography)
[![PyPI Downloads](https://static.pepy.tech/badge/ddcCryptography)](https://pepy.tech/projects/ddcCryptography)
[![codecov](https://codecov.io/gh/ddc/ddcCryptography/graph/badge.svg?token=Q25ZT1URLS)](https://codecov.io/gh/ddc/ddcCryptography)
[![CI/CD Pipeline](https://github.com/ddc/ddcCryptography/actions/workflows/workflow.yml/badge.svg)](https://github.com/ddc/ddcCryptography/actions/workflows/workflow.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ddc_ddcCryptography&metric=alert_status)](https://sonarcloud.io/dashboard?id=ddc_ddcCryptography)  
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A//actions-badge.atrox.dev/ddc/ddcCryptography/badge?ref=main&label=build&logo=none)](https://actions-badge.atrox.dev/ddc/ddcCryptography/goto?ref=main)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Python](https://img.shields.io/pypi/pyversions/ddcCryptography.svg)](https://www.python.org/downloads)

[![Support me on GitHub](https://img.shields.io/badge/Support_me_on_GitHub-154c79?style=for-the-badge&logo=github)](https://github.com/sponsors/ddc)

## Table of Contents

- [Install](#install)
- [Cryptography](#cryptography)
  - [Generate Private Key](#generate-private-key)
  - [Encode](#encode)
  - [Decode](#decode)
- [Development](#development)
  - [Building from Source](#building-from-source)
  - [Running Tests](#running-tests)
- [License](#license)
- [Support](#support)

# Install
```shell
pip install ddcCryptography
```

# Cryptography

## Generate Private Key
+ Generates a private key to be used instead of default one
+ But keep in mind that this private key WILL BE NEEDED TO DECODE FURTHER STRINGS
+ Example of custom private key as "my_private_key" bellow

```python
from ddcCryptography import Cryptography
cp = Cryptography()
cp.generate_private_key()
```



## Encode
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
 


## Decode
+ Decode a given string
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



# Development

### Building from Source
```shell
poetry build -f wheel
```

### Running Tests
```shell
poetry update --with test
poe tests
```



# License
Released under the [MIT License](LICENSE)



# Support
If you find this project helpful, consider supporting development:

- [GitHub Sponsor](https://github.com/sponsors/ddc)
- [ko-fi](https://ko-fi.com/ddcsta)
- [PayPal](https://www.paypal.com/ncp/payment/6G9Z78QHUD4RJ)
