import asyncio
import logging

import uvloop

from feedhandler import AsyncRealtimeOptimizedClient

logging.basicConfig(level=logging.INFO)


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
