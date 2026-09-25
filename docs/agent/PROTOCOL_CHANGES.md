# Protocol change proposals

The wire contract in `proto/central/agent/v1/` is shared by independently deployed agents and
servers, so it changes deliberately. Agent developers who need a change add a proposal below;
the server team reviews it, updates `proto/`, runs `make gen` and `buf breaking`, and implements
the server side. Until then, implement against the current contract.

Rules:

- Additive changes (new optional fields, new messages, new oneof cases, new enum values) are
  preferred and keep wire compatibility. Receivers must ignore unknown fields and treat unknown
  enum values as unsupported.
- Never renumber or reuse field numbers; reserve removed ones.
- Behavioural changes that older peers cannot handle must be negotiated via `Hello.features` /
  `HelloAck` or a new protocol version.

## Template

```
### <short title>

- Proposed by / date:
- Status: proposed | accepted | implemented | rejected
- Motivation: what cannot be done today and why it matters
- Change: messages/fields/RPCs (with proposed field numbers)
- Compatibility: how old agents / old servers behave
- Security considerations: new inputs, trust changes, limits
```

## Proposals

_None yet._
