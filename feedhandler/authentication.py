"""
This module provides asynchronous functions to authenticate and refresh the tokens for an Refinitiv Data Platform API.
It relies on environmental variables for configuration details such as the API's token URL, client ID, username, password,
and scope.

Usage:
Ensure all necessary environment variables are set before using this module. The module can raise `ConfigurationError` if any required
environment variables are missing.

Example:

```python
import asyncio
from feedhandler.authentication import authenticate, refresh

async def main():
    try:
        auth_response = await authenticate()
        print(f"Authenticated with token: {auth_response.access_token}")
    except AuthenticationError as e:
        print(f"Authentication failed: {e.message}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

For more information visit https://developers.lseg.com/en/api-catalog/refinitiv-data-platform/refinitiv-data-platform-apis/quick-start

"""

import base64
import logging
import os
from collections import namedtuple

import aiohttp
import aiohttp.client_exceptions

from feedhandler.exceptions import AuthenticationError, ConfigurationError

__slots__ = ['authenticate', 'refresh']

logger = logging.getLogger(__name__)

AuthenticationResponse = namedtuple(
    'AuthenticationResponse',
    ['access_token', 'refresh_token', 'expires_in', 'scope', 'token_type'],
)

TOKEN_URL = os.getenv('TOKEN_URL') or ''
CLIENT_ID = os.getenv('CLIENT_ID') or ''
USERNAME = os.getenv('ACCOUNT_ID') or ''
PASSWORD = os.getenv('PASSWORD') or ''
SCOPE = os.getenv('SCOPE') or ''

required_env_vars = [TOKEN_URL, CLIENT_ID, USERNAME, PASSWORD, SCOPE]

session: aiohttp.ClientSession | None = None


def get_or_create_session() -> aiohttp.ClientSession:
    global session
    if session is None or session.closed:
        session = aiohttp.ClientSession()
    return session


if not all(required_env_vars):
    logger.error(
        'Authentication Configuration Error: The application cannot proceed because it lacks complete authentication details.'
    )

    raise ConfigurationError(
        message='Authentication Configuration Error: The application cannot proceed because it lacks complete authentication details. This information is critical for securing and using external services.',
        recovery_suggestion=f'Verify and ensure that all necessary authentication variables {required_env_vars} are correctly set in your environment or in a .env file.',
    )


def get_auth_headers(client_id: str) -> dict[str, str]:
    """Get the authentication headers for the client_id

    Args:
        client_id (str): The client ID for which to generate the authentication headers.

    Returns:
        dict[str, str]:  A dictionary containing the necessary HTTP headers for authentication.
    """
    auth_string = base64.b64encode(bytes(f'{client_id}:', 'utf-8')).decode('utf-8')

    return {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Accept': 'application/json',
        'Authorization': f'Basic {auth_string}',
    }


def get_auth_payload(
    username: str, password: str, scope: str, take_exclusive_signon: bool
) -> dict[str, str | bool]:
    """Get the authentication payload for the username, password and scope

    Args:
        username (str): The username of the account for which the authentication token is requested.
        password (str): The password associated with the username for authentication.
        scope (str): The scope of the access request, which defines the level of access that the generated token will grant.

    Returns:
        dict[str, str]: A dictionary representing the payload needed to request an authentication token.
    """
    return {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': scope,
        'takeExclusiveSignOnControl': take_exclusive_signon,
    }


def get_refresh_payload(refresh_token: str) -> dict[str, str]:
    """Get the refresh payload for the refresh_token

    Args:
        refresh_token (str): The refresh token previously obtained during authentication. This token is used to request a new access token without requiring user credentials again.

    Returns:
        dict[str, str]: A dictionary containing the parameters required to obtain a new access token using a refresh token.
    """
    return {'grant_type': 'refresh_token', 'refresh_token': refresh_token}


async def authenticate() -> AuthenticationResponse:
    """Authenticate the user and return the access token

    Returns:
        AuthResponse: A named tuple containing the access token, refresh token, expiry time, scope and token type.
    """

    logger.debug('Authenticating')

    async with get_or_create_session() as session:
        try:
            async with session.post(
                TOKEN_URL,
                headers=get_auth_headers(CLIENT_ID),
                data=get_auth_payload(
                    USERNAME, PASSWORD, SCOPE, take_exclusive_signon=True
                ),
            ) as response:
                response.raise_for_status()

                auth_response_json = await response.json()

            if 'error' in auth_response_json:
                # Invalid username or password
                # Found temporary password. It must be changed. Input newPassword field to change password.
                # Faildc to change password. Reason: ERROR_NEWPASSWORD_MINCHARACTERS

                raise AuthenticationError(
                    message=auth_response_json['error_description']
                    if 'error_description' in auth_response_json
                    else auth_response_json['error'],
                    recovery_suggestion=None,
                ) from None

            return AuthenticationResponse(
                auth_response_json['access_token'],
                auth_response_json['refresh_token'],
                auth_response_json['expires_in'],
                auth_response_json['scope'],
                auth_response_json['token_type'],
            )

        except aiohttp.ClientError as client_err:
            logger.error(f'Error occurred while connecting: {client_err}')
            raise client_err
        except Exception as e:
            logger.error(f'Error occurred while authenticating: {e}')
            raise e


async def refresh(refresh_token: str) -> AuthenticationResponse:
    """Refresh the authentication token using the refresh token. If the refresh token has expired, a new authentication process is initiated.

    Args:
        refresh_token (str): The refresh token previously obtained during authentication. This token is used to request a new access token without requiring user credentials again.

    Returns:
        AuthResponse: A named tuple containing the access token, refresh token, expiry time, scope and token type.

    """

    async def handle_refresh_process(
        refresh_token: str,
    ) -> AuthenticationResponse | None:
        async with get_or_create_session() as session:
            try:
                async with session.post(
                    TOKEN_URL,
                    headers=get_auth_headers(CLIENT_ID),
                    data=get_refresh_payload(refresh_token),
                ) as response:
                    response.raise_for_status()
                    auth_response_json = await response.json()

                if 'error' in auth_response_json:
                    if auth_response_json['error'] == 'invalid_grant':
                        logger.error('Refresh token has expired')
                        return None
                    else:
                        raise AuthenticationError(
                            message=auth_response_json['error_description']
                            if 'error_description' in auth_response_json
                            else auth_response_json['error'],
                            recovery_suggestion=None,
                        ) from None

                return AuthenticationResponse(
                    auth_response_json['access_token'],
                    auth_response_json['refresh_token'],
                    auth_response_json['expires_in'],
                    auth_response_json['scope'],
                    auth_response_json['token_type'],
                )

            except aiohttp.ClientError as client_err:
                logger.error(f'Error occurred while connecting: {client_err}')
                raise client_err
            except Exception as e:
                logger.error(f'Error occurred while refreshing: {e}')
                raise e

    logger.info('Refreshing authentication token')

    if (auth_response := await handle_refresh_process(refresh_token)) is None:
        return await authenticate()
    else:
        return auth_response
