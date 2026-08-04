# mcp-pulsedive

Pulsedive MCP — threat-intelligence IOC enrichment (pulsedive.com)

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

## Tools

| Tool | Description |
|------|-------------|
| `pulsedive_indicator` | Is this IP/domain/URL/hash malicious — risk score + threats. Looks up an indicator of compromise (IOC) in Pulsedive and returns its risk level, contributing risk factors, associated threats, and intel feeds. Example: pulsedive_indicator({ indicator: "8.8.8.8", _apiKey: "your-key" }) |
| `pulsedive_explore` | Search Pulsedive threat DB with a query. Uses the Pulsedive Explore query language (boolean field filters) to find indicators matching criteria like type, risk, feed, or threat. Example: pulsedive_explore({ q: "type=domain and risk=high", limit: 20, _apiKey: "your-key" }) |

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "pulsedive": {
      "url": "https://gateway.pipeworx.io/pulsedive/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Pulsedive data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
