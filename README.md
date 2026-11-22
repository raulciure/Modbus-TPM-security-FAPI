# Modbus-TPM-security-FAPI
A Python-based bump-in-the-wire security solution, with TPM-based hardware security using tpm2-pytss FAPI, aimed at securing legacy TCP-based industrial communication protocols, with a primary focus on Modbus TCP.

## Dependencies
You can install the required Linux-level system tools and libraries using:
```bash
sudo apt update
sudo apt install -y \
  build-essential \
  pkg-config \
  python3-dev \
  python3-pip \
  python3-venv \
  libtss2-dev \
  libssl-dev \
  libjson-c-dev \
  libcurl4-openssl-dev \
  uuid-dev \
  tpm2-tools
```

The Python-level modules required are included in `requirements.txt`. These include:
- PyCryptodome [3.21.0](https://pypi.org/project/pycryptodome/3.21.0/)
- asn1crypto [1.5.1](https://pypi.org/project/asn1crypto/1.5.1/)
- cffi [2.0.0](https://pypi.org/project/cffi/2.0.0/)
- cryptography [48.0.0](https://pypi.org/project/cryptography/48.0.0/)
- packaging [26.2](https://pypi.org/project/packaging/26.2/)
- pycparser [3.0](https://pypi.org/project/pycparser/3.0/)
- PyYAML [6.0.3](https://pypi.org/project/PyYAML/6.0.3/)
- tpm2-pytss [2.3.0](https://pypi.org/project/tpm2-pytss/2.3.0/)

## Configuration
To make the project operational FAPI must be configured and provisioned accordingly.\
Based on the project's design, there should be two FAPI configuration files: `fapi-config-ecc.json` and `fapi-config-rsa.json` placed at `/usr/local/etc/tpm2-tss/`. The ECC and RSA SRK handles should have different addresses (e.g. `0x81000001` and `0x81000100`).\
Finally, either `tpm2_provision` or `sudo tpm2_provision` should be run (depending on the chosen paths in the FAPI config files).\
The following examples are provisioning using `sudo`, using Python for calling the provisioning method. This allows for testing the success of the installation of the Python-level required modules.

### Provision ECC profile:
```bash
sudo -H env TSS2_FAPICONF=/usr/local/etc/tpm2-tss/fapi-config-ecc.json .venv/bin/python
```
```python
from tpm2_pytss import FAPI
with FAPI() as fapi:
    fapi.provision(is_provisioned_ok=True)
```

### Provision RSA profile:
```bash
sudo -H env TSS2_FAPICONF=/usr/local/etc/tpm2-tss/fapi-config-rsa.json .venv/bin/python
```
```python
from tpm2_pytss import FAPI
with FAPI() as fapi:
    fapi.provision(is_provisioned_ok=True)
```

## Compatibility with other TPM libraries
This project should be compatible with other TPM libraries that make use of the Linux TPM kernel (`/dev/tpmrm0`).\
Compatibility was specifically confirmed with the [**wolfTPM**](https://github.com/wolfSSL/wolfTPM) library.