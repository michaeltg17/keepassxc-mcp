# MCP Server for KeePassXC

[![CI](https://github.com/michaeltg17/keepassxc-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/michaeltg17/keepassxc-mcp/actions/workflows/ci.yml)

Gives an AI agent a request → approve → merge path into a KeePassXC vault.

It uses keepassxc-cli — the official KeePassXC binary — for every kdbx operation, so this tool implements no crypto and never writes the vault itself.

The master password is only ever typed by a human in their own terminal, never seen by the agent.

See the [wiki](https://github.com/michaeltg17/keepassxc-mcp/wiki) for more info.

---

Built with [my AI setup](https://github.com/michaeltg17/my-AI-setup).
