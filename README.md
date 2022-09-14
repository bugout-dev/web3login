# web3-auth

Moonstream: Open source Web3 authorization library

## CLI

### Generate signature for registration

```bash
web3auth register -s .secrets/keyfile -p "${KEYFILE_PASSWORD}" | base64 -w 0
```

Output base64 string could be passed as `Authorization` header or verified with CLI.

### Verify registration signature

```bash
web3auth verify --schema registration --payload "${GENERATE_BASE64_SIGNATURE}"
```
