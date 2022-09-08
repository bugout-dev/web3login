import time
from typing import Any, Dict, Union, cast

import eth_keys
from eip712.messages import EIP712Message, _hash_eip191_message
from eth_account._utils.signing import sign_message_hash
from hexbytes import HexBytes
from web3 import Web3

from . import exceptions


# Authorization
AUTH_PAYLOAD_NAME = "MoonstreamAuthorization"
AUTH_VERSION = "1"
# By default, authorizations will remain active for 24 hours.
AUTH_DEADLINE_DEFAULT_INTERVAL = 60 * 60 * 24


class MoonstreamAuthorization(EIP712Message):
    """
    Login functionality from Moonstream for Web3 applications.

    Login flow relies on an Authorization header passed to API of the form:
    Authorization: moonstream <base64-encoded JSON>

    The schema for the JSON object will be as follows:
    {
        "address": "<address of account which signed the message>",
        "deadline": <epoch timestamp after which this header becomes invalid>,
        "signature": "<signed authorization message>"
    }

    Authorization messages will be generated pursuant to EIP712 using the following parameters:
    Domain separator - name: MoonstreamAuthorization, version: <Web3Auth version>
    Fields - address ("address" type), deadline: ("uint256" type)"""

    _name_: "string"
    _version_: "string"

    address: "address"
    deadline: "uint256"


# Sign Up
SIGNUP_PAYLOAD_NAME = "MoonstreamSignUp"
SIGNUP_VERSION = "1"


class MoonstreamSignUp(EIP712Message):
    """
    SignUp functionality from Moonstream for Web3 applications.

    Login flow relies on form passed to API.

    The schema for the JSON object will be as follows:
    {
        "address": "<address of account which signed the message>",
        "signature": "<signed authorization message>"
    }

    Authorization messages will be generated pursuant to EIP712 using the following parameters:
    Domain separator - name: MoonstreamSignUp, version: <Web3Auth version>
    Fields - address ("address" type)"""

    _name_: "string"
    _version_: "string"

    address: "address"


def sign_message(message_hash_bytes: HexBytes, private_key: HexBytes) -> HexBytes:

    eth_private_key = eth_keys.keys.PrivateKey(private_key)
    _, _, _, signed_message_bytes = sign_message_hash(
        eth_private_key, message_hash_bytes
    )
    return signed_message_bytes


def authorize(deadline: int, address: str, private_key: HexBytes) -> Dict[str, Any]:
    """
    Genereate Authortization message for address.
    """
    message = MoonstreamAuthorization(
        _name_=AUTH_PAYLOAD_NAME,
        _version_=AUTH_VERSION,
        address=address,
        deadline=deadline,
    )

    msg_hash_bytes = HexBytes(_hash_eip191_message(message.signable_message))

    signed_message = sign_message(msg_hash_bytes, private_key)

    api_payload: Dict[str, Any] = {
        "address": address,
        "deadline": deadline,
        "signed_message": signed_message.hex(),
    }

    return api_payload


def signup(address: str, private_key: HexBytes) -> Dict[str, Any]:
    """
    Genereate SignIn message for address.
    """
    message = MoonstreamSignUp(
        _name_=AUTH_PAYLOAD_NAME,
        _version_=AUTH_VERSION,
        address=address,
    )
    msg_hash_bytes = HexBytes(_hash_eip191_message(message.signable_message))

    signed_message = sign_message(msg_hash_bytes, private_key)

    api_payload: Dict[str, Any] = {
        "address": address,
        "signed_message": signed_message.hex(),
    }

    return api_payload


def verify(
    authorization_payload: Dict[str, Any],
    schema: Union[MoonstreamAuthorization, MoonstreamSignUp],
) -> bool:
    """
    Verifies provided signature from signer with correct address.
    """
    time_now = int(time.time())

    web3_client = Web3()
    address = Web3.toChecksumAddress(cast(str, authorization_payload["address"]))
    signature = cast(str, authorization_payload["signed_message"])

    if schema is MoonstreamAuthorization:
        deadline = cast(int, authorization_payload["deadline"])
        if deadline < time_now:
            raise exceptions.MoonstreamAuthorizationExpired("Deadline exceeded")
        message = schema(
            _name_=AUTH_PAYLOAD_NAME,
            _version_=AUTH_VERSION,
            address=address,
            deadline=deadline,
        )
    elif schema is MoonstreamSignUp:
        message = schema(
            _name_=AUTH_PAYLOAD_NAME,
            _version_=AUTH_VERSION,
            address=address,
        )
    else:
        raise exceptions.MoonstreamVerificationError("Unexcepted schema")

    signer_address = web3_client.eth.account.recover_message(
        message.signable_message, signature=signature
    )
    if signer_address != address:
        raise exceptions.MoonstreamVerificationError("Invalid signer")

    return True
