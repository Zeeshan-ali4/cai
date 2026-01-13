"""Example: connect to Metasploit RPC and search for modules."""
import asyncio
import os

from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, Runner
from cai.tools.command_and_control.metasploit_rpc import msf_rpc_call


async def main() -> None:
    agent = Agent(
        name="Metasploit RPC Agent",
        description="Agent that queries Metasploit RPC for authorized testing.",
        instructions=(
            "Use the msf_rpc_call tool to query Metasploit RPC. "
            "Only perform actions against authorized targets."
        ),
        tools=[msf_rpc_call],
        model=OpenAIChatCompletionsModel(
            model=os.getenv("CAI_MODEL", "qwen2.5:14b"),
            openai_client=AsyncOpenAI(),
        ),
    )

    result = await Runner.run(
        agent,
        "Search Metasploit modules for smb and return the top results.",
    )
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())