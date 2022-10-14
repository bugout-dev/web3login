import argparse
import base64
import getpass
import json
import time
from typing import Tuple

from eth_account import Account
from hexbytes import HexBytes

from .auth import AUTH_DEADLINE_DEFAULT_INTERVAL, authorize, verify


def decrypt_keystore(keystore_path: str, password: str) -> Tuple[str, HexBytes]:
    with open(keystore_path) as keystore_file:
        keystore_data = json.load(keystore_file)
    return keystore_data["address"], Account.decrypt(keystore_data, password)


def handle_authorize(args: argparse.Namespace) -> None:
    password = args.password
    if password is None:
        password = getpass.getpass()
    address, private_key = decrypt_keystore(args.signer, password)
    authorization_payload = authorize(
        deadline=args.deadline,
        address=address,
        application=args.application,
        private_key=private_key,
    )
    print(json.dumps(authorization_payload))


def handle_verify(args: argparse.Namespace) -> None:
    payload_json = base64.decodebytes(args.payload).decode("utf-8")
    payload = json.loads(payload_json)
    verify(authorization_payload=payload, application_to_check=args.application)
    print("Verified!")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Moonstream Web3 authorization and registration module"
    )
    subcommands = parser.add_subparsers()

    authorize_parser = subcommands.add_parser("authorize")
    authorize_parser.add_argument(
        "-a",
        "--application",
        default="",
        help="Application authorization belongs to, by default is equal to empty string.",
    )
    authorize_parser.add_argument(
        "-t",
        "--deadline",
        type=int,
        default=int(time.time()) + AUTH_DEADLINE_DEFAULT_INTERVAL,
        help="Authorization deadline (seconds since epoch timestamp), by default is equal to 24 hours.",
    )
    authorize_parser.add_argument(
        "-s",
        "--signer",
        required=True,
        help="Path to signer keyfile (or brownie account name).",
    )
    authorize_parser.add_argument(
        "-p",
        "--password",
        required=False,
        help="(Optional) password for signing account. If you don't provide it here, you will be prompte for it.",
    )
    authorize_parser.set_defaults(func=handle_authorize)

    verify_parser = subcommands.add_parser("verify")
    verify_parser.add_argument(
        "-a",
        "--application",
        default="",
        help="Application authorization belongs to, by default is equal to empty string.",
    )
    verify_parser.add_argument(
        "--payload",
        type=lambda s: s.encode(),
        required=True,
        help="Base64-encoded payload to verify",
    )
    verify_parser.set_defaults(func=handle_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
