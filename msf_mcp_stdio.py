#!/usr/bin/env python3
import sys, json, os, time

from pymetasploit3.msfrpc import MsfRpcClient

MSF_HOST = os.environ.get("MSF_RPC_HOST", "192.168.3.20")
MSF_PORT = int(os.environ.get("MSF_RPC_PORT", "55553"))
MSF_USER = os.environ.get("MSF_RPC_USER", "msf")
MSF_PASS = os.environ.get("MSF_RPC_PASS", os.environ.get("MSF_RPC_PASSWORD", "msfrpc"))

def env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

MSF_SSL = env_bool("MSF_RPC_SSL", True)

client = None
console_id = None

def connect():
    global client
    if client is None:
        client = MsfRpcClient(MSF_PASS, server=MSF_HOST, port=MSF_PORT, ssl=MSF_SSL, username=MSF_USER)

def get_console():
    global console_id
    connect()
    if console_id is None:
        console_id = client.consoles.console().cid
    return client.consoles.console(console_id)

def console_exec(cmd: str, timeout=30):
    c = get_console()
    c.write(cmd if cmd.endswith("\n") else cmd + "\n")
    deadline = time.time() + timeout
    out = ""
    while time.time() < deadline:
        time.sleep(0.2)
        r = c.read()
        out += r.get("data", "")
        if not r.get("busy", True):
            break
    return out.strip()

TOOLS = [
    {
        "name": "msf_search",
        "description": "Search Metasploit modules by keyword",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "msf_console_command",
        "description": "Run a raw msfconsole command (persistent console)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "msf_module_info",
        "description": "Show detailed info for a Metasploit module (equivalent to: info <module>)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_fullname": {
                    "type": "string",
                    "description": "e.g. exploit/windows/smb/ms17_010_eternalblue",
                }
            },
            "required": ["module_fullname"],
        },
    },
    {
        "name": "msf_module_options",
        "description": "Show options for a module (equivalent to: use <module>; show options)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_fullname": {
                    "type": "string",
                    "description": "e.g. exploit/windows/smb/ms17_010_eternalblue",
                }
            },
            "required": ["module_fullname"],
        },
    },
    {
        "name": "msf_use_exploit",
        "description": "Use a Metasploit exploit (equivalent to: use <exploit>)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_fullname": {
                    "type": "string",
                    "description": "e.g. exploit/windows/smb/ms17_010_eternalblue",
                }
            },
            "required": ["module_fullname"],
        },
    },
    {
        "name": "msf_run_module",
        "description": "Run a module safely (default: check if supported, else run -j).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_fullname": {"type": "string"},
                "options": {"type": "object"},
                "action": {"type": "string", "enum": ["check", "run"], "default": "check"},
                "timeout": {"type": "integer", "default": 60},
            },
            "required": ["module_fullname"],
        },
    },
    {
        "name": "msf_list_sessions",
        "description": "List active Metasploit sessions",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    }
]

def mcp_result_text(text: str):
    # MCP "content" is a list; CAI expects this shape
    return {"content": [{"type": "text", "text": text}]}

def handle(req):
    method = req.get("method")
    rid = req.get("id")

    if method == "initialize":
        # Minimal MCP initialize response
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": req.get("params", {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "metasploit-mcp", "version": "0.1.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = req.get("params", {}) or {}
        name = params.get("name")
        args = params.get("arguments", {}) or {}

        try:
            if name == "msf_search":
                q = args["query"]
                out = console_exec(f"search {q}", timeout=20)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}

            if name == "msf_console_command":
                cmd = args["command"]
                t = int(args.get("timeout", 30))
                out = console_exec(cmd, timeout=t)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}

            if name == "msf_module_info":
                m = args["module_fullname"].strip()
                out = console_exec(f"info {m}", timeout=25)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}

            if name == "msf_module_options":
                m = args["module_fullname"].strip()
                # Use + show options (single persistent console)
                out = console_exec(f"use {m}\nshow options", timeout=25)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}
            
            if name == "msf_use_exploit":
                m = args["module_fullname"].strip()
                out = console_exec(f"use {m}", timeout=15)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}
            
            if name == "msf_run_module":
                m = args["module_fullname"].strip()
                opts = args.get("options", {}) or {}
                action = (args.get("action", "check") or "check").strip().lower()
                timeout = int(args.get("timeout", 60))

                cmds = [f"use {m}"]
                for k, v in opts.items():
                    cmds.append(f"set {k} {v}")

                if action == "check":
                    cmds.append("check")
                else:
                    cmds.append("run")
                out = console_exec("\n".join(cmds), timeout=timeout)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}
            
            if name == "msf_list_sessions":
                out = console_exec("sessions -l", timeout=20)
                return {"jsonrpc": "2.0", "id": rid, "result": mcp_result_text(out or "(no output)")}

            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}}

    # Notifications like "initialized" may arrive; ignore them.
    if rid is None:
        return None

    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown method: {method}"}}

def main():
    # Important: do NOT print banners; only JSON-RPC on stdout.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle(req)
        if resp is None:
            continue
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()