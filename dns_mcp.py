#!/usr/bin/env python3
"""
MCP server for the central DNS resolver.

It exposes the resolver's HTTP API as Model Context Protocol tools so an AI
assistant can view and update the DNS records this network serves.

Transport: stdio (JSON-RPC 2.0, newline-delimited). No third-party packages.

Configuration (environment variables):
    DNS_API_URL     Base URL of the DNS resolver API   (default http://127.0.0.1:8080)
    DNS_API_TOKEN   Token, if the API requires one      (default unset)

Example opencode config:
    "mcp": {
      "dns": {
        "type": "local",
        "command": ["python", "C:\\\\path\\\\to\\\\dns_mcp.py"],
        "enabled": true,
        "env": { "DNS_API_URL": "http://127.0.0.1:8080" }
      }
    }
"""

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import quote

API_URL = os.environ.get("DNS_API_URL", "http://127.0.0.1:8080")
API_TOKEN = os.environ.get("DNS_API_TOKEN", "")
DEBUG = os.environ.get("DNS_MCP_DEBUG", "")
PROTOCOL_VERSION = "2024-11-05"

NOTIFICATION = object()


class ToolError(Exception):
    pass


def dbg(msg):
    if DEBUG:
        sys.stderr.write("[dns-mcp] {}\n".format(msg))
        sys.stderr.flush()


def _request(method, path, body=None):
    url = API_URL.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if API_TOKEN:
        req.add_header("X-API-Token", API_TOKEN)
        req.add_header("Authorization", "Bearer " + API_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"error": "HTTP {}".format(exc.code)}
        return exc.code, payload
    except Exception as exc:
        return 0, {"error": "cannot reach DNS API at {}: {}".format(API_URL, exc)}


def _need(args, key):
    value = args.get(key)
    if value is None or value == "":
        raise ToolError("missing required field '{}'".format(key))
    return value


def _record_path(name):
    return "/api/records/" + quote(str(name).strip(), safe="*.")


# ------------------------------- tool impls -------------------------------


def t_list_records(args):
    status, data = _request("GET", "/api/records")
    if status != 200:
        raise ToolError(json.dumps(data))
    return json.dumps(data.get("records", {}), indent=2)


def t_get_record(args):
    name = _need(args, "name")
    status, data = _request("GET", _record_path(name))
    if status != 200:
        raise ToolError(json.dumps(data))
    return json.dumps(data.get("record"), indent=2)


def t_set_record(args):
    name = _need(args, "name")
    body = {k: args[k] for k in ("A", "AAAA", "TXT", "CNAME", "merge", "block") if k in args}
    if not body:
        raise ToolError("provide at least one of A, AAAA, TXT, CNAME or block")
    status, data = _request("PUT", _record_path(name), body)
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Record saved for {}:\n{}".format(name, json.dumps(data.get("record"), indent=2))


def t_add_txt(args):
    name = _need(args, "name")
    value = _need(args, "value")
    body = {"TXT": [value], "merge": bool(args.get("merge", True))}
    status, data = _request("POST", _record_path(name), body)
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Added TXT to {}:\n{}".format(name, json.dumps(data.get("record"), indent=2))


def t_delete_record(args):
    name = _need(args, "name")
    status, data = _request("DELETE", _record_path(name))
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Removed the custom record for {}; it now resolves normally.".format(name)


def t_status(args):
    status, data = _request("GET", "/api/status")
    if status != 200:
        raise ToolError(json.dumps(data))
    return json.dumps(data, indent=2)


def t_set_upstream(args):
    body = {k: args[k] for k in ("upstream", "upstream_port", "ttl") if k in args}
    if not body:
        raise ToolError("provide upstream, upstream_port and/or ttl")
    status, data = _request("POST", "/api/settings", body)
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Settings updated:\n{}".format(json.dumps(data.get("settings"), indent=2))


def t_reload(args):
    status, data = _request("POST", "/api/reload")
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Reloaded DNS records from disk."


def t_get_queries(args):
    params = []
    for key in ("since", "until", "limit"):
        if key in args and args[key] is not None:
            params.append("{}={}".format(key, args[key]))
    path = "/api/queries" + (("?" + "&".join(params)) if params else "")
    status, data = _request("GET", path)
    if status != 200:
        raise ToolError(json.dumps(data))
    text = json.dumps(data, indent=2)
    return text[:40000]


def t_set_targets(args):
    targets = args.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ToolError("provide 'targets' as a non-empty array of resolver addresses")
    status, data = _request("POST", "/api/settings", {"intercept_ips": targets})
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Resolver addresses updated:\n{}".format(json.dumps(data.get("settings"), indent=2))


def t_clear_recording(args):
    status, data = _request("POST", "/api/queries/clear")
    if status != 200:
        raise ToolError(json.dumps(data))
    return "Cleared the recorded DNS request history."


# ------------------------------- tool schema ------------------------------

TOOLS = [
    {
        "name": "list_dns_records",
        "description": (
            "List every DNS record served by this network's central DNS resolver. "
            "Shows each domain's A, AAAA, TXT and CNAME values, whether it forwards "
            "other lookups upstream, and whether it is blocked."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_dns_record",
        "description": "Get the central DNS resolver's record for a single domain.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Domain name, e.g. example.com or *.example.com"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "set_dns_record",
        "description": (
            "Create or replace the complete record for a domain on the central DNS "
            "resolver. Supply any of A, AAAA, TXT, CNAME or block. Set merge=true to "
            "keep the domain's normal public records and add these on top; otherwise "
            "this is authoritative for the domain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Domain name, e.g. example.com or *.example.com"},
                "A": {"type": "array", "items": {"type": "string"}, "description": "IPv4 addresses"},
                "AAAA": {"type": "array", "items": {"type": "string"}, "description": "IPv6 addresses"},
                "TXT": {"type": "array", "items": {"type": "string"}, "description": "TXT string values"},
                "CNAME": {"type": "string", "description": "CNAME target domain"},
                "merge": {"type": "boolean", "description": "Also resolve the domain's normal public records"},
                "block": {"type": "boolean", "description": "Answer the domain with NXDOMAIN"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "add_dns_txt_record",
        "description": (
            "Add a TXT string to a domain on the central DNS resolver while its other "
            "records (A, AAAA, MX, ...) keep resolving normally. Use for ownership or "
            "verification values, notes, SPF-style entries, etc."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Domain name"},
                "value": {"type": "string", "description": "TXT value to add"},
                "merge": {"type": "boolean", "description": "Keep the domain's public records (default true)"},
            },
            "required": ["name", "value"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_dns_record",
        "description": "Remove a domain's custom record from the central DNS resolver so it resolves normally again.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Domain name"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_dns_status",
        "description": "Report the central DNS resolver's status: listening port, upstream resolver, TTL, record count, the resolver addresses it answers for, and how many requests it has recorded.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "set_dns_targets",
        "description": (
            "Set which resolver addresses the central DNS service answers for, e.g. "
            "[\"1.1.1.1\", \"8.8.8.8\"]. Requests to these addresses are handled by this "
            "service instead of going out to the public resolver."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Resolver addresses the service should answer for",
                }
            },
            "required": ["targets"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_dns_queries",
        "description": (
            "View requests recorded by the central DNS resolver within a time window. "
            "Times are Unix epoch seconds (since/until); omit them for the most recent "
            "requests. Returns each request's time, client, domain, type, action and result."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "number", "description": "Start time (epoch seconds)"},
                "until": {"type": "number", "description": "End time (epoch seconds)"},
                "limit": {"type": "integer", "description": "Maximum rows to return (default 5000)"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "clear_dns_recording",
        "description": "Clear the central DNS resolver's recorded request history.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "set_dns_upstream",
        "description": "Set the upstream resolver and/or default TTL used for domains that have no custom record.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "upstream": {"type": "string", "description": "Upstream resolver IP"},
                "upstream_port": {"type": "integer", "description": "Upstream port (default 53)"},
                "ttl": {"type": "integer", "description": "Default TTL in seconds"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "reload_dns",
        "description": "Reload the central DNS resolver's records from its configuration file on disk.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]

TOOL_IMPL = {
    "list_dns_records": t_list_records,
    "get_dns_record": t_get_record,
    "set_dns_record": t_set_record,
    "add_dns_txt_record": t_add_txt,
    "delete_dns_record": t_delete_record,
    "get_dns_status": t_status,
    "set_dns_upstream": t_set_upstream,
    "reload_dns": t_reload,
    "set_dns_targets": t_set_targets,
    "get_dns_queries": t_get_queries,
    "clear_dns_recording": t_clear_recording,
}


# ------------------------------- JSON-RPC ---------------------------------


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def dispatch(method, params):
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "central-dns", "version": "1.0.0"},
        }
    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return NOTIFICATION
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        impl = TOOL_IMPL.get(name)
        if impl is None:
            return {"content": [{"type": "text", "text": "unknown tool '{}'".format(name)}], "isError": True}
        try:
            text = impl(params.get("arguments") or {})
            return {"content": [{"type": "text", "text": text}], "isError": False}
        except ToolError as exc:
            return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        except Exception as exc:  # noqa: BLE001
            return {"content": [{"type": "text", "text": "error: {}".format(exc)}], "isError": True}
    if method == "resources/list":
        return {"resources": []}
    if method == "prompts/list":
        return {"prompts": []}
    raise KeyError(method)


def main():
    dbg("started; API_URL={}".format(API_URL))
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            dbg("bad json: {!r}".format(raw[:200]))
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        is_notification = "id" not in msg
        try:
            result = dispatch(method, msg.get("params") or {})
        except KeyError:
            if not is_notification:
                send({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": -32601, "message": "method not found: {}".format(method)}})
            continue
        except Exception as exc:  # noqa: BLE001
            if not is_notification:
                send({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": -32603, "message": str(exc)}})
            continue
        if result is NOTIFICATION or is_notification:
            continue
        send({"jsonrpc": "2.0", "id": msg_id, "result": result})


if __name__ == "__main__":
    main()
