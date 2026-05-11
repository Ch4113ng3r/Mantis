# MANTIS

**AI-Powered Penetration Testing Framework**

Modular AI-driven Network, application & code Testing Intelligence System.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure
export ANTHROPIC_API_KEY="sk-ant-..."
mantis setup

# Check dependencies
mantis doctor

# Run an engagement
mantis engage --mode webapp --target http://testphp.vulnweb.com --depth quick
```

## Engagement Modes

| Mode | Description |
|------|-------------|
| `network` | Network infrastructure pentest |
| `webapp` | Internal web application pentest |
| `webapp_external` | External web app with full recon |
| `api` | API pentest (OpenAPI/GraphQL/Postman) |
| `code_review` | Source code security review |
| `code_review+webapp` | Code review + web app with correlation |
| `full` | Everything combined |

## Hunt Mode

```bash
mantis hunt --vuln SSTI --url "https://target.com/search?q="
mantis hunt --vuln BOLA --url "https://api.target.com" --functionality "user endpoints"
```

## Architecture

Pure Python. No LangGraph. No Rust. The ReAct agent is a while loop.
SQLite for checkpoints. networkx for knowledge graph. httpx for everything HTTP.

See the MANTIS Complete Guide PDF for full architecture, source code, and setup instructions.

## License

MIT — Use responsibly. Only test targets you own or have written authorization for.
