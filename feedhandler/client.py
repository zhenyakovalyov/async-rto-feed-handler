import asyncio
import logging
import os
from collections.abc import AsyncIterator
from typing import Self

import orjson
from websockets.client import WebSocketClientProtocol, connect
from websockets.typing import Subprotocol

from feedhandler.authentication import AuthenticationResponse, authenticate, refresh
from feedhandler.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

WS_URL = os.getenv('WS_URL') or ''


if not WS_URL:
    raise ConfigurationError(
        'Websocket Configuration Error: WebSocket URL is not set, check the environment or .env file for required variables',
        'Verify and ensure that WS_URL variable is correctly set in your environment or in an .env file. It should contain the URL for the websocket server.',
    )


class AuthenticationManager:
    """
    AuthenticationManager is responsible for obtraining an access token and handling its subsequent refreshes.

    Args:
        outgoing_queue (asyncio.PriorityQueue): A queue to submit generated authentication or refresh messages to
        ready_event (asyncio.Event): An event for authentication readiness, i.e. a trigger for the workflow to start

    Functions:
        authenticate: Obtain an access token and submit a message to the outgoing queue
        refresh: A task to periodically refresh an access token
    """

    def __init__(
        self, outgoing_queue: asyncio.PriorityQueue, ready_event: asyncio.Event
    ):
        self.__auth_func = authenticate
        self.__refresh_func = refresh

        self.__queue = outgoing_queue
        self.__ready = ready_event

        self.__refresh_token: str | None = None
        self.__expires_in: str | None = None

    async def authenticate(self):
        """Authenticate the user and submit a message to the outgoing queue"""

        await self.__ready.wait()
        logger.debug('Ready for authentication')

        auth_response = await self.__auth_func()
        self.__refresh_token = auth_response.refresh_token
        self.__expires_in = auth_response.expires_in

        logger.debug('Access token received')

        message = {
            'ID': 1,
            'Domain': 'Login',
            'Key': {
                'NameType': 'AuthnToken',
                'Elements': {
                    'ApplicationId': '256',
                    'Position': '127.0.0.1/net',
                    'AuthenticationToken': f'{auth_response.access_token}',
                },
            },
        }

        self.__queue.put_nowait((1, message))

        logger.debug('Authentication message submitted to queue')

    async def refresh(self):
        """Periodically refresh the access token and submit a message to the outgoing queue"""

        await self.__ready.wait()

        refresh_interval = (
            (int(self.__expires_in) - 60) if self.__expires_in else (600 - 60)
        )

        try:
            while True:
                await asyncio.sleep(refresh_interval)

                if not self.__refresh_token:
                    raise ValueError(
                        'Refresh token is not set, check authentication state'
                    )

                response: AuthenticationResponse = await self.__refresh_func(
                    self.__refresh_token
                )
                self.__expires_in = response.expires_in

                logger.debug('Access token received with refresh token')
                self.__refresh_token = response.refresh_token

                message = {
                    'ID': 1,
                    'Domain': 'Login',
                    'Key': {
                        'NameType': 'AuthnToken',
                        'Elements': {
                            'ApplicationId': '256',
                            'Position': '127.0.0.1/net',
                            'AuthenticationToken': f'{response.access_token}',
                        },
                    },
                    'Refresh': True,
                }

                self.__queue.put_nowait((1, message))

                logger.debug('Refresh authentication message submitted to queue')
        except asyncio.CancelledError:
            logger.debug('Refresh task cancelled')


class MessageHandler:
    """

    MessageHandler is responsible for routing messages to the appropriate handlers
    and providing appropriate responses.

    Args:
        outgoing_queue (asyncio.PriorityQueue): (asyncio.PriorityQueue): A queue to submit protocol messages
        incoming_queue (asyncio.Queue): A queue to submit messages to be processed
        ready_for_subscriptions_event (asyncio.Event): An event for a subscription readiness signal
        shutdown_received_event (asyncio.Event): An event for a shutdown signal

    """

    def __init__(
        self,
        outgoing_queue: asyncio.PriorityQueue,
        incoming_queue: asyncio.Queue,
        ready_for_subscriptions_event: asyncio.Event,
        shutdown_received_event: asyncio.Event,
    ):
        self.__ready_for_subscriptions = ready_for_subscriptions_event
        self.__shutdown_received = shutdown_received_event

        self.__send_q = outgoing_queue
        self.__recv_q = incoming_queue

        self.__handlers = {
            'Ping': self.__handle_ping,
            'Refresh': self.__handle_refresh,
            'Update': self.__handle_update,
            'Status': self.__handle_status,
            'Error': self.__handle_error,
        }

        self.__max_sequence_seen: int = 1

    async def sequence_number(self) -> AsyncIterator[int]:
        # a batch response assigns an ID automatically per each item,
        # so we need to track the maximum ID seen so far
        # and ensure that the generator always returns an unused ID

        for i in range(2, 1_000_000_000):
            if i > self.__max_sequence_seen:
                yield i

    def handle(self, message: dict):
        """Route message to the appropriate handler based on its type."""

        try:
            if (
                'ID' in message
                and (sequence_id := int(message['ID'])) > self.__max_sequence_seen
            ):
                logger.debug(
                    f'New sequence ID: {sequence_id}, max: {self.__max_sequence_seen}'
                )

                self.__max_sequence_seen = sequence_id
        except Exception as e:
            logger.error(e)

        handler = self.__handlers.get(message['Type'], self.__handle_unknown)

        handler(message)

    def __handle_ping(self, message: dict):
        logger.debug('Ping message received')
        self.__send_q.put_nowait((1, {'Type': 'Pong'}))

    def __handle_refresh(self, message: dict):
        domain = message.get('Domain')

        if domain == 'Login':
            self.__ready_for_subscriptions.set()
        elif domain is None:
            pass
        else:
            logger.debug(f'Refresh message received on a known domain: {domain}')

    def __handle_update(self, message: dict):
        self.__recv_q.put_nowait(message)

    def __handle_status(self, message: dict):
        if 'Domain' in message and message['Domain'] == 'Login':
            if 'State' in message and message['State']['Stream'] == 'Closed':
                logger.error('Login stream closed')
                self.__shutdown_received.set()
            else:
                ...

        logger.debug(
            f"""Status message received: 
            {
                orjson.dumps(message, option=orjson.OPT_INDENT_2).decode()
            }
            """
        )

    def __handle_error(self, message: dict):
        logger.debug(
            f"""Error message received: 
            {
                orjson.dumps(message, option=orjson.OPT_INDENT_2).decode()
            }
            """
        )

    def __handle_unknown(self, message: dict):
        logger.warning(f'Unknown message type: {message["Type"]}')
        logger.debug(
            f"""Unknown message received: 
            {
                orjson.dumps(message, option=orjson.OPT_INDENT_2).decode()
            }
            """
        )


class SentinelMessage: ...


class AsyncRealtimeOptimizedClient:
    """
    AsyncRealtimeOptimized is responsible for establishing a connection to the WebSocket server,
    authenticating, and handling incoming and outgoing messages.

    Args:
        items (List[str]): A list of items to subscribe to
        fields (Optional[List[str]]): A list of fields to subscribe to

    Usage:
        async with AsyncRealtimeOptimizedClient(['IBM.N', 'MSFT.O'], ['DSPLY_NAME', 'BID', 'ASK']) as f:
            async for message in f:
                print(message)
    """

    def __init__(self, items: list[str], fields: list[str]) -> None:
        if not all([items, fields]) or any([len(items) == 0, len(fields) == 0]):
            raise ValueError('Items or fields are empty')

        self.__items = items
        self.__fields = fields

        self.__ws: WebSocketClientProtocol | None = None

        self.__recv_q: asyncio.Queue = asyncio.Queue()
        self.__send_q: asyncio.Queue = asyncio.PriorityQueue()

        self.__connected = asyncio.Event()
        self.__ready_for_subscriptions = asyncio.Event()
        self.__iterator_stopped = asyncio.Event()
        self.__shutdown_received = asyncio.Event()

        self.__tasks: list[asyncio.Task] = []

        self.__auth_manager = AuthenticationManager(self.__send_q, self.__connected)

        self.__message_handler = MessageHandler(
            self.__send_q,
            self.__recv_q,
            self.__ready_for_subscriptions,
            self.__shutdown_received,
        )

    async def __aenter__(self) -> Self:
        self.__ws = await connect(
            WS_URL,
            subprotocols=[Subprotocol('tr_json2')],
            extra_headers={'User-Agent': 'Python'},
            ping_interval=None,
        )

        logger.debug(f'Connected to the websocket {WS_URL}')

        self.__connected.set()

        await self.__auth_manager.authenticate()
        asyncio.create_task(self.__shutdown(), name='shutdown')

        self.__tasks.extend(
            [
                asyncio.create_task(self.__receive_messages(), name='receive_messages'),
                asyncio.create_task(self.__send_messages(), name='send_messages'),
                asyncio.create_task(
                    self.__auth_manager.refresh(), name='refresh_token'
                ),
            ]
        )

        asyncio.create_task(
            self.__subscribe(self.__items, self.__fields), name='subscribe'
        )

        return self

    async def __aexit__(self, exc_type, exc_val, traceback):
        await self.__connected.wait()

        if not self.__ws:
            raise Exception('No websocket connection')

        message = {'ID': 1, 'Type': 'Close', 'Domain': 'Login'}

        await self.__send_q.put((1, message))

        logger.debug('Shutdown message sent')
        self.__shutdown_received.set()

    def __aiter__(self):
        return self

    async def __anext__(self):
        message = await self.__recv_q.get()

        if message is SentinelMessage:
            self.__iterator_stopped.set()
            logger.debug('Iterator stopped')
            raise StopAsyncIteration

        self.__recv_q.task_done()
        return message

    async def __receive_messages(self) -> None:
        """
        Receives messages from the websocket and submits them to the queue.
        """
        await self.__connected.wait()
        if not self.__ws:
            raise Exception('No websocket connection')

        logger.debug('Ready to process incoming messages')

        try:
            while True:
                try:
                    raw_message = await self.__ws.recv()
                    parsed_messages = orjson.loads(raw_message)
                    for message in parsed_messages:
                        self.__message_handler.handle(message)
                except Exception as e:
                    logger.error(f'Error while receiving messages: {e}')
                    self.__shutdown_received.set()
                    break
        except asyncio.CancelledError:
            logger.debug('Receive message task cancelled')

    async def __send_messages(self) -> None:
        """
        Sends messages from the queue to the websocket.
        """
        await self.__connected.wait()

        if not self.__ws:
            raise Exception('No websocket connection')

        logger.debug('Ready to send messages')
        try:
            while True:
                _, message = await self.__send_q.get()
                await self.__ws.send(orjson.dumps(message))
                logger.debug(
                    f"""Message sent: 
                        {
                            orjson.dumps(message, option=orjson.OPT_INDENT_2).decode()
                        }
                    """
                )
                self.__send_q.task_done()
        except asyncio.CancelledError:
            logger.debug('Send message task cancelled')
        except Exception as e:
            logger.error(e)
            raise e

    async def __subscribe(
        self, items: list[str], fields: list[str] | None = None
    ) -> None:
        """
        Subscribe to the specified items and fields.
        """
        await self.__ready_for_subscriptions.wait()

        sequence_number = await anext(self.__message_handler.sequence_number())

        message = {
            'ID': sequence_number,
            'Key': {'Name': items[0] if len(items) == 1 else items},
        }

        if fields:
            message['View'] = fields

        self.__send_q.put_nowait((100, message))

        logger.debug(
            f'Subscription message submitted to the outgoing queue for {items}'
        )

    async def __shutdown(self) -> None:
        """
        Shutdown the feed handler.
        """

        await self.__shutdown_received.wait()
        logger.debug('Ready for shutdown')

        # send a sentinel value to the receive queue to stop the iteration
        self.__recv_q.put_nowait(SentinelMessage())
        await self.__iterator_stopped.wait()

        logger.debug('Sentinel value submitted to the incoming queue')

        for i, task in enumerate(self.__tasks):
            task.cancel()
            logger.debug(f'Task {i} cancellation requested')
            try:
                await task  # wait for the task to be cancelled
            except Exception as e:
                logger.error(f'Exception during task cancellation: {e}')

        logger.debug('All tasks cancelled')

        if self.__ws and not self.__ws.closed:
            await self.__ws.close()
            logger.debug('WebSocket connection closed.')
