# MCP Server for KeePassXC

Gives an AI agent a request → approve → merge path into a KeePassXC vault.

It uses keepassxc-cli — the official KeePassXC binary — for every kdbx operation, so this tool implements no crypto and never writes the vault itself.

The master password is only ever typed by a human in their own terminal, never seen by the agent.

---

Built with the help of local AI using https://github.com/michaeltg17/best-model-dual-3090 and OpenCode.

See the [wiki](https://github.com/michaeltg17/keepassxc-mcp/wiki) for docs.
