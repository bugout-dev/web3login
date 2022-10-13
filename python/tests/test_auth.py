import os
import time
import unittest
from typing import Any, Dict

from web3login import auth, exceptions
from web3login.cli import decrypt_keystore

CURRENT_DIR = os.path.dirname(__file__)

web3_accounts = [
    {
        "keyfile": f"{CURRENT_DIR}/keyfile-0xBfA9E7453aD94fd0931b3933ae88553D732d1d93",
        "address": "0xBfA9E7453aD94fd0931b3933ae88553D732d1d93",
        "password": "kompotkot",
    },
    {
        "keyfile": f"{CURRENT_DIR}/keyfile-0x5A4F6f18c2Bd7A44A90F56D9b65BC4B3849C5258",
        "address": "0x5A4F6f18c2Bd7A44A90F56D9b65BC4B3849C5258",
        "password": "moonstream",
    },
]


class TestAuth(unittest.TestCase):
    def test_authorize(
        self,
        application: str = "",
        deadline: int = int(time.time()) + auth.AUTH_DEADLINE_DEFAULT_INTERVAL,
    ) -> Dict[str, Any]:
        web3_account = web3_accounts[0]
        address, private_key = decrypt_keystore(
            web3_account.get("keyfile", ""), web3_account.get("password", "")
        )
        self.assertEqual(address, web3_account.get("address", "")[2:].lower())

        authorization_payload = auth.authorize(
            deadline=deadline,
            address=address,
            application=application,
            private_key=private_key,
        )
        self.assertEqual(
            authorization_payload.get("address"),
            web3_account.get("address", "")[2:].lower(),
        )
        self.assertEqual(authorization_payload.get("deadline"), deadline)
        self.assertEqual(authorization_payload.get("application"), application)

        return authorization_payload

    def test_verify(self):
        application = "test_app"
        deadline = int(time.time()) + 10
        authorization_payload = self.test_authorize(
            application=application, deadline=deadline
        )

        # Verified
        verified = auth.verify(
            authorization_payload=authorization_payload,
            application_to_check=application,
        )
        self.assertEqual(verified, True)

    def test_verify_wrong_app(self):
        application = "test_app"
        deadline = int(time.time()) + 10
        authorization_payload = self.test_authorize(
            application=application, deadline=deadline
        )

        # Not verified with wrong application
        with self.assertRaises(exceptions.Web3AuthorizationWrongApplication) as context:
            auth.verify(
                authorization_payload=authorization_payload,
                application_to_check="wrong_app",
            )
        self.assertTrue("Wrong application provided" in str(context.exception))

    def test_verify_deadline_exceeded(self):
        application = "test_app"
        deadline = int(time.time()) - 1
        authorization_payload = self.test_authorize(
            application=application, deadline=deadline
        )

        # Not verified with wrong application
        with self.assertRaises(exceptions.Web3AuthorizationExpired) as context:
            auth.verify(
                authorization_payload=authorization_payload,
                application_to_check=application,
            )
        self.assertTrue("Deadline exceeded" in str(context.exception))

    def test_verify_wrong_signer(self):
        authorization_payload = self.test_authorize()

        # Not verified with wrong signer
        authorization_payload["address"] = web3_accounts[1].get("address")
        with self.assertRaises(exceptions.Web3VerificationError) as context:
            auth.verify(
                authorization_payload=authorization_payload,
                application_to_check="",
            )
        self.assertTrue("Invalid signer" in str(context.exception))

    def test_verify_wrong_signer_silent(self):
        authorization_payload = self.test_authorize()

        # Not verified with wrong signer in silent mode
        authorization_payload["address"] = web3_accounts[1].get("address")
        verified = auth.verify(
            authorization_payload=authorization_payload,
            application_to_check="",
            silent=True,
        )
        self.assertFalse(verified)


if __name__ == "__main__":
    unittest.main()
