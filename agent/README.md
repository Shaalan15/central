# central-agent (reserved)

This directory is reserved for the Central machine agent, which is built separately by
another contributor/agent instance following
[`docs/agent/AGENT_BUILD_PROMPT.md`](../docs/agent/AGENT_BUILD_PROMPT.md).

Do not add server or UI code here. The agent is a Go module (`github.com/Shaalan15/central/agent`)
that joins the repository's Go workspace (`go.work`) and imports the generated protocol code from
`gen/go`.
