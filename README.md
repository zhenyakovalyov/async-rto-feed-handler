# Real-time Optimised (RTO) Feed Handler

## Description

This project provides an asynchronous feed handler for the Real-time Optimised (RTO) feed from the LSEG's RDP API. The feed handler is designed to connect to the RTO feed and receive real-time market data updates via the web socket connection. 

## Disclaimer

* The project is for personal use and is not officially affiliated with, maintained, or endorsed by London Stock Exchange Group. For official resources and support, please refer to https://developers.lseg.com/en/api-catalog/refinitiv-data-platform/refinitiv-data-platform-apis.
* The code is provided as-is without any guarantees, and it might not reflect the current or official capabilities of the API.
* Updates to the code might not be regular and feedback might not be promptly addressed.
* The code is not be suitable for production use and should be used at your own risk.

## Getting Started

### Prerequisites

- Python 3.12:
    - \[optional] uvloop for a faster event loop
- poetry package manager with `poetry-plugin-dotenv` installed
- a valid RDP API account with access to the real-time optimised (RTO) feed

### Installation

Clone the repository and install the required dependencies:

```
git clone https://github.com/zhenyakovalyov/async-rto-feed-handler.git
cd async-rto-feed-handler
poetry install
```

### Environment Variables

Create a `.env` file in the project root directory (use `.env.example` as a template) and add the following environment variables:

* `TOKEN_URL`: the URL to obtain the access token, e.g. `https://api.refinitiv.com/auth/oauth2/v1/token`
* `CLIENT_ID`: a generated app key, if you have it; if not, you can generate a new one at http://apidocs.refinitiv.com
* `ACCOUNT_ID`: your username or a machine ID, if you have it
* `PASSWORD`: your password
* `SCOPE`: the scope of the access token, e.g. `trapi.streaming.pricing.read`
* `WS_URL`: the URL to connect to the RTO feed, e.g. `wss://eu-west-1-aws-1-lrg.optimized-pricing-api.refinitiv.net:443/WebSocket`

For more information, please refer to the official quick start guide https://developers.lseg.com/en/api-catalog/refinitiv-data-platform/refinitiv-data-platform-apis/quick-start

### Running the demo

Execute the demo.py script to start receiving real-time updates:

```bash
poetry run python demo.py
```

Output example:

```
{'ID': 4, 'Type': 'Update', 'UpdateType': 'Unspecified', 'DoNotConflate': True, 'Key': {'Service': 'ELEKTRON_DD', 'Name': 'GBP='}, 'SeqNumber': 3374, 'Fields': {'BID': 1.2554, 'ASK': 1.2558}}
{'ID': 6, 'Type': 'Update', 'UpdateType': 'Unspecified', 'DoNotConflate': True, 'Key': {'Service': 'ELEKTRON_DD', 'Name': 'JPY='}, 'SeqNumber': 39406, 'Fields': {'BID': 156.19, 'ASK': 156.22}}
```

### Running with Docker

Build the Docker image:

```bash
docker build -t async-rto-fh .
```

Run the Docker container:

```bash
docker run --env-file .env -d async-rto-fh
```

### Usage

```python
import asyncio
import logging

import uvloop

from feedhandler import AsyncRealtimeOptimizedClient

logging.basicConfig(level=logging.DEBUG)


async def main():
    async with AsyncRealtimeOptimizedClient(
        items=['EUR=', 'GBP=', 'CHF=', 'JPY='], fields=['BID', 'ASK']
    ) as feed:
        async for msg in feed:
            print(msg)


if __name__ == '__main__':
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        try:
            runner.run(main())
        except KeyboardInterrupt:
            print('Shutting down...')
            runner.close()
```

## License

This project is licensed under the MIT license. Please see the LICENSE file for more information.


## Contact

If you have any specific questions about this project, feel free to reach out to me via e-mail <github.compound383@passinbox.com>.