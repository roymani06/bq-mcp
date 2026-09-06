"""Microsoft Entra ID (Azure AD) JWT Authentication and JWKS Validator."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
    PyJWKClientError,
)

from config.settings import SETTINGS, SecurityConfig

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when Entra ID JWT validation fails."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class EntraTokenValidator:
    """Validates inbound Microsoft Entra ID bearer tokens against public JWKS endpoints."""

    def __init__(
        self,
        config: Optional[SecurityConfig] = None,
        jwks_client: Optional[jwt.PyJWKClient] = None,
    ) -> None:
        self.config = config or SETTINGS.security
        self.jwks_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/discovery/v2.0/keys"
        self._jwks_client = jwks_client or jwt.PyJWKClient(
            uri=self.jwks_url,
            cache_keys=True,
            cache_jwk_set=True,
            lifespan=float(self.config.jwks_cache_ttl_seconds),
        )

    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a Microsoft Entra ID access token and return extracted claims.

        Args:
            token: Raw JWT token string from Authorization header.

        Returns:
            Validated claims dictionary including extracted identity.

        Raises:
            AuthenticationError: If token is missing, expired, signed by unknown key,
                                or fails issuer/audience verification.
        """
        # Dev-mode bypass if auth is disabled in config
        if not self.config.enable_auth:
            logger.debug("Authentication is disabled in config; returning mock dev claims")
            return {
                "sub": "dev-user-001",
                "upn": "dev@local.internal",
                "email": "dev@local.internal",
                "name": "Dev User (Auth Disabled)",
                "oid": "00000000-0000-0000-0000-000000000000",
                "tid": self.config.tenant_id,
                "auth_disabled": True,
            }

        if not token or not token.strip():
            raise AuthenticationError("Authorization token is missing or empty.", status_code=401)

        token = token.strip()

        # 1. Extract unverified header to ensure 'kid' and 'alg' are present
        try:
            unverified_header = jwt.get_unverified_header(token)
        except InvalidTokenError as e:
            logger.warning("Failed to parse JWT header: %s", e)
            raise AuthenticationError(f"Malformed JWT header: {e}", status_code=401) from e

        kid = unverified_header.get("kid")
        if not kid:
            raise AuthenticationError("JWT header is missing required 'kid' key identifier.", status_code=401)

        alg = unverified_header.get("alg")
        if alg != "RS256":
            raise AuthenticationError(
                f"Unsupported JWT algorithm '{alg}'. Only 'RS256' is accepted.",
                status_code=401,
            )

        # 2. Fetch public key from Entra JWKS
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except PyJWKClientError as e:
            logger.warning("JWKS lookup error for kid '%s': %s", kid, e)
            raise AuthenticationError(
                f"Unable to locate public signing key for key identifier '{kid}': {e}",
                status_code=401,
            ) from e
        except Exception as e:
            logger.error("Unexpected error retrieving signing key: %s", e)
            raise AuthenticationError(f"Error resolving public signing key: {e}", status_code=401) from e

        # 3. Build accepted audiences and issuers
        accepted_audiences = [
            self.config.client_id,
            f"api://{self.config.client_id}",
        ]
        accepted_issuers = self.config.get_formatted_issuers()

        # 4. Decode and cryptographically verify signature, audience, issuer, and expiration
        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=accepted_audiences,
                issuer=accepted_issuers,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "iss", "aud"],
                },
            )
        except ExpiredSignatureError as e:
            logger.warning("Token expired: %s", e)
            raise AuthenticationError("Token has expired.", status_code=401) from e
        except InvalidAudienceError as e:
            logger.warning("Token audience mismatch. Expected one of %s: %s", accepted_audiences, e)
            raise AuthenticationError(
                f"Token audience mismatch. Expected {self.config.client_id}.",
                status_code=403,
            ) from e
        except InvalidIssuerError as e:
            logger.warning("Token issuer mismatch. Expected one of %s: %s", accepted_issuers, e)
            raise AuthenticationError(
                f"Token issuer mismatch. Token was not issued by accepted Entra tenant.",
                status_code=403,
            ) from e
        except InvalidTokenError as e:
            logger.warning("Invalid token: %s", e)
            raise AuthenticationError(f"Token validation failed: {e}", status_code=401) from e
        except Exception as e:
            logger.error("Unexpected exception during token verification: %s", e)
            raise AuthenticationError(f"Authentication failed: {e}", status_code=401) from e

        # 5. Extract and normalize identity
        identity = self.extract_identity(claims)
        claims["identity"] = identity
        logger.debug("Successfully authenticated Entra user identity: %s", identity)
        return claims

    @staticmethod
    def extract_identity(claims: Dict[str, Any]) -> str:
        """Extract user principal name, preferred username, email, or subject from claims."""
        for field in ("upn", "preferred_username", "email", "unique_name", "sub", "oid"):
            val = claims.get(field)
            if val and isinstance(val, str):
                return val
        return "unknown_principal"


# Global validator instance
TOKEN_VALIDATOR = EntraTokenValidator()
