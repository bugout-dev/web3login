# web3login python

Open source Web3 authorization Python library.

## CLI

### Generate the signature

```bash
web3login authorize \
    --application "<your_application_name_or_any_string>" \
    --deadline "<unix_timestamp_until_signature_will_be_active>" \
    --signer .secrets/keyfile -p "${KEYFILE_PASSWORD}" | base64 -w 0
```

Output base64 string could be passed as `Authorization` header or verified with CLI.

### Verify the signature

```bash
web3login verify \
    --application "<your_application_name_or_any_string>" \
    --payload "${GENERATED_BASE64_SIGNATURE}"
```
