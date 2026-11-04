"""
client/cli.py
-------------
[C2] Command-line interface for the client agent.

Run:
    python -m client.cli

Commands (once logged in):
    /chat <message>          — broadcast
    /dm <username> <message> — direct message
    /file <username> <path>  — send file
    /quit                    — exit

TODO (C — 24–26/10): wire up to ClientAgent methods.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main():
    print("Collaboration Client — CO3093")
    print("TODO: implement CLI in C2")


if __name__ == "__main__":
    asyncio.run(main())
