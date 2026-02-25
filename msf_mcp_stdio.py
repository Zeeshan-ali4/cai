#!/usr/bin/env python3
"""
MCP stdio server for Metasploit
Communicates with CAI via stdio, connects to msfrpcd via RPC.
"""

import sys
import json
import os
import time

# ---------------------------------------------------------------------------
# Try to import pymetasploit3; give a clear error if it's missing
# ---------------------------------------------------------------------------
try:
    from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError
except ImportError:
    sys.stderr.write(
        "[msf_mcp] ERROR: pymetasploit3 not installed. "
        "Run: pip install pymetasploit3\n"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Connection config — override via environment variables if needed:
#   MSF_RPC_HOST, MSF_RPC_PORT, MSF_RPC_PASSWORD, MSF_RPC_SSL
# ---------------------------------------------------------------------------
MSF_HOST = os.environ.get("MSF_RPC_HOST", "192.168.3.20")
MSF_PORT = int(os.environ.get("MSF_RPC_PORT", "55553"))
MSF_PASS = os.environ.get("MSF_RPC_PASSWORD", "msfrpc")
MSF_SSL  = os.environ.get("MSF_RPC_SSL", "false").lower() == "true"


class MetasploitMCP:
    def __init__(self):
        self.client = None
        self._console_id = None
        self._connect()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _connect(self):
        """Attempt to connect to msfrpcd, retrying a few times on startup."""
        for attempt in range(1, 6):
            try:
                self.client = MsfRpcClient(
                    MSF_PASS,
                    server=MSF_HOST,
                    port=MSF_PORT,
                    ssl=MSF_SSL,
                )
                sys.stderr.write(
                    f"[msf_mcp] Connected to msfrpcd at {MSF_HOST}:{MSF_PORT}\n"
                )
                return
            except Exception as e:
                sys.stderr.write(
                    f"[msf_mcp] Connection attempt {attempt}/5 failed: {e}\n"
                )
                if attempt < 5:
                    time.sleep(3)
        sys.stderr.write("[msf_mcp] Could not connect to msfrpcd. Exiting.\n")
        sys.exit(1)

    def _ensure_connected(self):
        if self.client is None:
            self._connect()

    def _get_console(self):
        """Get or create a persistent msfconsole session via RPC."""
        self._ensure_connected()
        if self._console_id is None:
            console = self.client.consoles.console()
            self._console_id = console.cid
        return self.client.consoles.console(self._console_id)

    def _console_exec(self, command, timeout=30):
        """
        Send a command to the persistent console and collect output.
        Polls until the console is no longer busy or timeout is reached.
        """
        console = self._get_console()
        console.write(command)

        deadline = time.time() + timeout
        output = ""
        while time.time() < deadline:
            time.sleep(0.5)
            data = console.read()
            output += data.get("data", "")
            if not data.get("busy", True):
                # Drain any remaining output
                time.sleep(0.3)
                data = console.read()
                output += data.get("data", "")
                break

        return output.strip() if output.strip() else "(no output)"

    # ------------------------------------------------------------------
    # MCP protocol
    # ------------------------------------------------------------------

    def handle_message(self, message):
        try:
            msg = json.loads(message)
            msg_type = msg.get("type")

            if msg_type == "list_tools":
                return self.list_tools()
            elif msg_type == "call_tool":
                return self.call_tool(msg.get("name"), msg.get("arguments", {}))
            else:
                return {"error": f"Unknown message type: {msg_type}"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}
        except Exception as e:
            return {"error": str(e)}

    def list_tools(self):
        tools = [
            {
                "name": "msf_search",
                "description": "Search for Metasploit modules by keyword",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (e.g. 'windows smb', 'eternalblue')"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "msf_console_command",
                "description": "Run any raw msfconsole command in a persistent session",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "msfconsole command to run (e.g. 'use exploit/...', 'set RHOSTS ...')"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Max seconds to wait for output (default 30)"
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "msf_use_exploit",
                "description": "Select an exploit module and show its info/options",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exploit_path": {
                            "type": "string",
                            "description": "Module path (e.g. exploit/windows/smb/ms17_010_eternalblue)"
                        }
                    },
                    "required": ["exploit_path"]
                }
            },
            {
                "name": "msf_run_exploit",
                "description": "Configure and run an exploit with the given options",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exploit_path": {
                            "type": "string",
                            "description": "Module path"
                        },
                        "options": {
                            "type": "object",
                            "description": "Key/value pairs to set (e.g. {\"RHOSTS\": \"192.168.3.11\", \"LHOST\": \"192.168.3.5\"})"
                        },
                        "payload": {
                            "type": "string",
                            "description": "Optional payload path (e.g. linux/x86/meterpreter/reverse_tcp)"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Seconds to wait for exploit output (default 60)"
                        }
                    },
                    "required": ["exploit_path", "options"]
                }
            },
            {
                "name": "msf_list_sessions",
                "description": "List all active Meterpreter/shell sessions",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "msf_session_command",
                "description": "Run a command inside an active Meterpreter session",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Session ID from msf_list_sessions"
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to run in the session (e.g. 'sysinfo', 'getuid', 'shell')"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Seconds to wait for output (default 15)"
                        }
                    },
                    "required": ["session_id", "command"]
                }
            },
            {
                "name": "msf_db_status",
                "description": "Check Metasploit database connection status",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "msf_hosts",
                "description": "List all hosts in the Metasploit database",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "msf_vulns",
                "description": "List all vulnerabilities recorded in the Metasploit database",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
        ]
        return {"type": "tools", "tools": tools}

    def call_tool(self, name, arguments):
        try:
            self._ensure_connected()

            # ---- search ----
            if name == "msf_search":
                query = arguments.get("query", "")
                output = self._console_exec(f"search {query}", timeout=20)
                return {"type": "result", "content": output}

            # ---- raw console command ----
            elif name == "msf_console_command":
                command = arguments.get("command", "")
                timeout = int(arguments.get("timeout", 30))
                output = self._console_exec(command, timeout=timeout)
                return {"type": "result", "content": output}

            # ---- use exploit + show info ----
            elif name == "msf_use_exploit":
                exploit = arguments.get("exploit_path", "")
                output = self._console_exec(f"use {exploit}\nshow options", timeout=15)
                return {"type": "result", "content": output}

            # ---- configure + run exploit ----
            elif name == "msf_run_exploit":
                exploit  = arguments.get("exploit_path", "")
                options  = arguments.get("options", {})
                payload  = arguments.get("payload", "")
                timeout  = int(arguments.get("timeout", 60))

                cmds = [f"use {exploit}"]
                for k, v in options.items():
                    cmds.append(f"set {k} {v}")
                if payload:
                    cmds.append(f"set PAYLOAD {payload}")
                cmds.append("run -j")          # run as background job

                output = self._console_exec("\n".join(cmds), timeout=timeout)
                return {"type": "result", "content": output}

            # ---- list sessions ----
            elif name == "msf_list_sessions":
                sessions = self.client.sessions.list
                if not sessions:
                    return {"type": "result", "content": "No active sessions."}
                lines = []
                for sid, info in sessions.items():
                    lines.append(
                        f"[{sid}] type={info.get('type')} "
                        f"via={info.get('via_exploit')} "
                        f"target={info.get('target_host')} "
                        f"info={info.get('info')}"
                    )
                return {"type": "result", "content": "\n".join(lines)}

            # ---- run command in session ----
            elif name == "msf_session_command":
                sid     = str(arguments.get("session_id", ""))
                command = arguments.get("command", "")
                timeout = int(arguments.get("timeout", 15))

                sessions = self.client.sessions.list
                if sid not in sessions:
                    return {"type": "error", "content": f"Session {sid} not found"}

                session = self.client.sessions.session(sid)
                session.write(command)
                time.sleep(1)
                deadline = time.time() + timeout
                output = ""
                while time.time() < deadline:
                    chunk = session.read()
                    output += chunk
                    if chunk:
                        time.sleep(0.5)
                    else:
                        break
                return {"type": "result", "content": output.strip() or "(no output)"}

            # ---- db_status ----
            elif name == "msf_db_status":
                output = self._console_exec("db_status", timeout=10)
                return {"type": "result", "content": output}

            # ---- hosts ----
            elif name == "msf_hosts":
                output = self._console_exec("hosts", timeout=10)
                return {"type": "result", "content": output}

            # ---- vulns ----
            elif name == "msf_vulns":
                output = self._console_exec("vulns", timeout=10)
                return {"type": "result", "content": output}

            else:
                return {"type": "error", "content": f"Unknown tool: {name}"}

        except MsfRpcError as e:
            return {"type": "error", "content": f"MsfRpcError: {e}"}
        except Exception as e:
            return {"type": "error", "content": str(e)}

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                response = self.handle_message(line.strip())
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

            except KeyboardInterrupt:
                break
            except Exception as e:
                sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    server = MetasploitMCP()
    server.run()