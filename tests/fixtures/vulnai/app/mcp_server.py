"""Ops MCP server (deliberately vulnerable: see README.md)."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def run(command: str) -> str:
    """Run a maintenance command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout   # planted: any command


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file for the assistant."""
    return open(path).read()                                            # planted: any path, no allow-list


if __name__ == "__main__":
    mcp.run(transport="sse")
