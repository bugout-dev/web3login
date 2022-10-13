import base64
import json
import logging
from typing import Awaitable, Callable, Dict, Optional

from fastapi import Request, Response
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED
from web3 import Web3

from ..auth import verify
from ..exceptions import Web3AuthorizationExpired, Web3VerificationError

logger = logging.getLogger(__name__)


class OAuth2Web3Signature(OAuth2):
    """
    Extended FastAPI OAuth2 middleware to support
    Web3 base64 signature in Authorization header.
    """

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "web3":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "web3"},
                )
            else:
                return None
        return param


class OAuth2BearerOrWeb3(OAuth2):
    """
    Extended FastAPI OAuth2 middleware to support Bearer token
    or Web3 base64 signature in Authorization header.
    """

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or (
            scheme.lower() != "web3" and scheme.lower() != "bearer"
        ):
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "web3/bearer"},
                )
            else:
                return None
        return param


class Web3AuthorizationMiddleware(BaseHTTPMiddleware):
    """
    Checks the authorization header on the request. It it represents
    a correctly signer message, adds address and deadline attributes to the request.state.
    Otherwise raises a 403 error.
    """

    def __init__(
        self, app, whitelist: Optional[Dict[str, str]] = None, application: str = ""
    ):
        self.whitelist: Dict[str, str] = {}
        if whitelist is not None:
            self.whitelist = whitelist
        self.application = application
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ):
        # Filter out whitelisted endpoints to bypass web3 authorization
        path = request.url.path.rstrip("/")
        method = request.method

        if path in self.whitelist.keys() and self.whitelist[path] == method:
            return await call_next(request)

        raw_authorization_header = request.headers.get("authorization")

        if raw_authorization_header is None:
            return Response(
                status_code=403, content="No authorization header passed with request"
            )

        authorization_header_components = raw_authorization_header.split()
        if (
            len(authorization_header_components) != 2
            or authorization_header_components[0].lower() != "web3"
        ):
            return Response(
                status_code=403,
                content="Incorrect format for authorization header. Expected 'Authorization: web3 <base64_encoded_json_payload>'",
            )

        try:
            json_payload_str = base64.b64decode(
                authorization_header_components[-1]
            ).decode("utf-8")

            json_payload = json.loads(json_payload_str)
            verified = verify(
                authorization_payload=json_payload,
                application_to_check=self.application,
            )
            address = json_payload.get("address")
            deadline = json_payload.get("deadline")
            application = json_payload.get("application")
            if address is not None:
                address = Web3.toChecksumAddress(address)
            else:
                raise Exception("Address in payload is None")
        except Web3VerificationError as e:
            logger.info("Web3 authorization verification error: %s", e)
            return Response(status_code=403, content="Invalid authorization header")
        except Web3AuthorizationExpired as e:
            logger.info("Web3 authorization expired: %s", e)
            return Response(status_code=403, content="Authorization expired")
        except Exception as e:
            logger.error("Unexpected exception: %s", e)
            return Response(status_code=500, content="Internal server error")

        request.state.address = address
        request.state.deadline = deadline
        request.state.application = application
        request.state.verified = verified
        request.state.signature = authorization_header_components[-1]

        return await call_next(request)
