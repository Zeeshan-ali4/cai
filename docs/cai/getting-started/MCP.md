# MCP

CAI supports the Model Context Protocol (MCP) for integrating external tools and services with AI agents. MCP is supported via two transport mechanisms:

1. **SSE (Server-Sent Events)** - For web-based servers that push updates over HTTP connections:
```bash
CAI>/mcp load http://localhost:9876/sse burp
```

2. **STDIO (Standard Input/Output)** - For local inter-process communication:
```bash
CAI>/mcp load stdio myserver python mcp_server.py
```

Once connected, you can add the MCP tools to any agent:
```bash
CAI>/mcp add burp redteam_agent
Adding tools from MCP server 'burp' to agent 'Red Team Agent'...
                                 Adding tools to Red Team Agent
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool                              ┃ Status ┃ Details                                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ send_http_request                 │ Added  │ Available as: send_http_request                 │
│ create_repeater_tab               │ Added  │ Available as: create_repeater_tab               │
│ send_to_intruder                  │ Added  │ Available as: send_to_intruder                  │
│ url_encode                        │ Added  │ Available as: url_encode                        │
│ url_decode                        │ Added  │ Available as: url_decode                        │
│ base64encode                      │ Added  │ Available as: base64encode                      │
│ base64decode                      │ Added  │ Available as: base64decode                      │
│ generate_random_string            │ Added  │ Available as: generate_random_string            │
│ output_project_options            │ Added  │ Available as: output_project_options            │
│ output_user_options               │ Added  │ Available as: output_user_options               │
│ set_project_options               │ Added  │ Available as: set_project_options               │
│ set_user_options                  │ Added  │ Available as: set_user_options                  │
│ get_proxy_http_history            │ Added  │ Available as: get_proxy_http_history            │
│ get_proxy_http_history_regex      │ Added  │ Available as: get_proxy_http_history_regex      │
│ get_proxy_websocket_history       │ Added  │ Available as: get_proxy_websocket_history       │
│ get_proxy_websocket_history_regex │ Added  │ Available as: get_proxy_websocket_history_regex │
│ set_task_execution_engine_state   │ Added  │ Available as: set_task_execution_engine_state   │
│ set_proxy_intercept_state         │ Added  │ Available as: set_proxy_intercept_state         │
│ get_active_editor_contents        │ Added  │ Available as: get_active_editor_contents        │
│ set_active_editor_contents        │ Added  │ Available as: set_active_editor_contents        │
└───────────────────────────────────┴────────┴─────────────────────────────────────────────────┘
Added 20 tools from server 'burp' to agent 'Red Team Agent'.
CAI>/agent 13
CAI>Create a repeater tab
```

You can list all active MCP connections and their transport types:
```bash
CAI>/mcp list
```

https://github.com/user-attachments/assets/386a1fd3-3469-4f84-9396-2a5236febe1f

## Example: Controlling Chrome with CAI

1) Install node, following the instructions on the [official site](https://nodejs.org/en/download/current)

2) Install Chrome (Chromium is not compatible with this functionality)

3) Run the following commands:
	```
	/mcp load stdio devtools npx chrome-devtools-mcp@latest
	/mcp add devtools redteam_agent
	/agent redteam_agent
	```

Once this is done, you will have full control of Chrome using the red team agent.


## Example: Using Metasploit from CAI (via MCP + msfrpcd)

For CTF workflows, the clean integration pattern is:

`CAI Agent ↔ MCP Server ↔ Metasploit RPC (msfrpcd) ↔ CTF target`

This keeps the LLM on structured MCP tool calls instead of brittle free-form shell commands.

### 1) Start Metasploit RPC securely

Run `msfrpcd` locally (or in a controlled jump host) and bind it to localhost whenever possible:

```bash
msfrpcd -P 'STRONG_PASSWORD' -S -a 127.0.0.1 -p 55553
```

- `-S` enables SSL/TLS.
- Restrict network exposure (`127.0.0.1`) and use port-forwarding if CAI is remote.
- Use dedicated CTF credentials and rotate them often.

### 2) Build a minimal MCP wrapper server for Metasploit

Create a local MCP server (Python/Node) that connects to Metasploit RPC and exposes a **safe subset** of tools. Recommended first tool surface:

- `msf_list_modules(type, search?)`
- `msf_module_info(module_fullname)`
- `msf_module_options(module_fullname)`
- `msf_configure_module(module_fullname, options)`
- `msf_run_module(module_fullname, options, run_as_job=true)`
- `msf_list_jobs()`
- `msf_stop_job(job_id)`
- `msf_list_sessions()`
- `msf_read_session(session_id, timeout_s=1)`
- `msf_write_session(session_id, command)`
- `msf_stop_session(session_id)`

Design notes for the wrapper:

- Validate parameter schemas strictly (host/IP/port/module names).
- Enforce allowlists/denylists for module families if needed.
- Add operation timeouts and return explicit error objects.
- Record a per-tool audit log (timestamp, module, target, operator context).

### 3) MCP STDIO transport (recommended for local/dev)

Run your wrapper as a local process and load it into CAI:

```bash
/mcp load stdio metasploit python /path/to/metasploit_mcp_server.py
/mcp tools metasploit
/mcp add metasploit redteam_agent
/agent redteam_agent
```

If your wrapper needs env vars (RPC password, host, port), set them before launching CAI.

### 4) CTF operating workflow

1. Recon outside Metasploit (or through other MCP tools).
2. Ask CAI to enumerate relevant modules for discovered services/CVEs.
3. Have CAI inspect module options and propose minimal required settings.
4. Run exploit module as job.
5. Poll jobs/sessions via MCP tools.
6. Interact with sessions through explicit read/write session tools.
7. Stop jobs/sessions and export activity summary.

Example prompt once tools are attached:

```text
Use metasploit MCP tools only. Target 10.10.10.42 for SMB vulnerabilities.
List candidate exploit modules, explain tradeoffs, configure the best candidate,
run it as a job, and report back new sessions.
```

### 5) Guardrails and safety recommendations

- Limit usage to authorized CTF/lab targets only.
- Prefer read-only/intel tools first, then controlled exploitation.
- Block dangerous post modules unless explicitly required.
- Implement network allowlist checks in MCP wrapper (e.g., only RFC1918/CTF ranges).
- Add an approval flag in MCP tool input for any destructive action.

### 6) Troubleshooting checklist

- `msfrpcd` unreachable: verify bind address/port/TLS and local firewall.
- Auth failures: confirm password/user and RPC protocol compatibility.
- Tools not visible in CAI: run `/mcp list`, `/mcp status`, `/mcp tools metasploit`.
- Agent not using tools: re-run `/mcp add metasploit redteam_agent` and keep prompts explicit: “use metasploit MCP tools only”.
- Stale/failed wrapper: `/mcp remove metasploit` then reload.