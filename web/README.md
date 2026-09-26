# Central web UI

The Angular 22 frontend for Central. In production it is compiled to static assets and embedded
into the `central` Go binary, so there is no separate web server to deploy.

## Requirements

- Node.js 24 LTS (`.nvmrc` at the repo root) — Angular 22 requires `^22.22.3 || ^24.15.0 || >=26`.

## Development

```bash
npm ci
npm start          # http://localhost:4200, proxies /api and /ws to the Go server on :8080
```

Run the backend alongside it with `make dev` from the repo root (see the top-level README).

## Scripts

| Command                | What it does                                              |
| ---------------------- | --------------------------------------------------------- |
| `npm run build`        | Production build into `dist/browser` (hashed, SRI-signed) |
| `npm run test:ci`      | Unit tests (Vitest + jsdom), single run                   |
| `npm test`             | Unit tests in watch mode                                  |
| `npm run lint`         | ESLint (angular-eslint, typescript-eslint)                |
| `npm run format:check` | Prettier check                                            |

## Conventions

- Standalone components, signals, zoneless change detection and `OnPush` (the v22 default).
- File names follow the Angular v20+ style guide (`home.ts`, not `home.component.ts`).
- No inline scripts or third-party CDNs: the server sends a nonce-based Content-Security-Policy,
  and fonts are self-hosted from npm packages.
- Generated API clients live in `src/gen` (produced by `make gen`; do not edit by hand).
