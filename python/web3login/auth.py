import time
from typing import Any, Dict, cast

import eth_keys  # type: ignore
from eip712.messages import EIP712Message, _hash_eip191_message
from eth_account._utils.signing import sign_message_hash
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3

from . import exceptions

# Authorization
AUTH_PAYLOAD_NAME = "Web3Authorization"
AUTH_VERSION = "1"
# By default, authorizations will remain active for 24 hours.
AUTH_DEADLINE_DEFAULT_INTERVAL = 60 * 60 * 24


class Web3Authorization(EIP712Message):
    """
    Authorization functionality for Web3 applications.

    Login flow relies on an Authorization header passed to API of the form:
    Authorization: Web3 <base64-encoded JSON>

    The schema for the JSON object will be as follows:
    {
        "address": "<address of account which signed the message>",

        "deadline": <epoch timestamp after which this header becomes invalid, by default is equal to 24 hours>,
        "application": <application belong to, by default is equal to empty string>,

        "signature": "<signed authorization message>"
    }

    Authorization messages will be generated pursuant to EIP712 using the following parameters:
    Domain separator - name: Web3Authorization, version: <Web3Login version>
    Fields - address ("address" type), deadline: ("uint256" type), application: ("string" type)
    """

    _name_: "string"  # type: ignore
    _version_: "string"  # type: ignore

    address: "address"  # type: ignore

    # Optional fields
    # deadline by default is set to 60 * 60 * 24
    # application by default is set to empty string
    deadline: "uint256"  # type: ignore
    application: "string"  # type: ignore


def sign_message(message_hash_bytes: HexBytes, private_key: HexBytes) -> HexBytes:

    eth_private_key = eth_keys.keys.PrivateKey(private_key)
    _, _, _, signed_message_bytes = sign_message_hash(
        eth_private_key, message_hash_bytes
    )
    return signed_message_bytes


def authorize(
    deadline: int, address: str, application: str, private_key: HexBytes
) -> Dict[str, Any]:
    """
    Generates Authorization message for address.
    """
    message = Web3Authorization(
        _name_=AUTH_PAYLOAD_NAME,
        _version_=AUTH_VERSION,
        address=address,
        deadline=deadline,
        application=application,
    )  # type: ignore

    msg_hash_bytes = HexBytes(_hash_eip191_message(message.signable_message))

    signed_message = sign_message(msg_hash_bytes, private_key)

    api_payload: Dict[str, Any] = {
        "address": address,
        "deadline": deadline,
        "application": application,
        "signed_message": signed_message.hex(),
    }

    return api_payload


def to_checksum_address(address: str) -> ChecksumAddress:
    return Web3.toChecksumAddress(cast(str, address))


def verify(
    authorization_payload: Dict[str, Any],
    application_to_check: str,
    silent: bool = False,
) -> bool:
    """
    Verifies provided signature from signer with correct address.
    """
    time_now = int(time.time())

    web3_client = Web3()
    address = to_checksum_address(authorization_payload["address"])
    signature = cast(str, authorization_payload["signed_message"])

    deadline = cast(int, authorization_payload["deadline"])
    if deadline < time_now:
        if silent:
            return False
        raise exceptions.Web3AuthorizationExpired("Deadline exceeded")
    application = cast(str, authorization_payload["application"])
    if application_to_check != application:
        if silent:
            return False
        raise exceptions.Web3AuthorizationWrongApplication("Wrong application provided")
    message = Web3Authorization(
        _name_=AUTH_PAYLOAD_NAME,
        _version_=AUTH_VERSION,
        address=address,
        deadline=deadline,
        application=application,
    )  # type: ignore

    signer_address = web3_client.eth.account.recover_message(
        message.signable_message, signature=signature
    )
    if signer_address != address:
        if silent:
            return False
        raise exceptions.Web3VerificationError("Invalid signer")

    return True
