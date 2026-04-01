# ZeroJ Use Case Demos — Shared NFRs

All package names start with `com.bloxbean.cardano.zeroj.usecases`
GroupId: `com.bloxbean.cardano`

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend | Spring Boot | 3.4.x |
| Java | GraalVM | 25 (`sdk use java 25.0.2-graal`) |
| Build | Gradle | 9.2+ |
| Frontend | Svelte 5 + Vite | Latest |
| Frontend packaging | Build to `src/main/resources/static/`, served by Spring Boot |
| ZK Proofs | zeroj (local SNAPSHOT from `../zeroj`) | 0.1.0-SNAPSHOT |
| On-chain scripts | Julc | 0.1.0-pre10 |
| Cardano client | cardano-client-lib | 0.8.0-pre3 |
| Cardano networks | Yaci DevKit (local) + Preprod (testnet) |
| Wallet (Yaci) | Hardcoded mnemonic for testing |
| Wallet (Preprod) | MeshJS connect-wallet in browser |
| Testing | JUnit (backend), Playwright MCP (UI) |
| GraalVM native | Optional but structure must support it |
| Deployment | Single JAR (frontend embedded) or separate frontend |
| HTTP client (frontend) | Native `fetch` API — **NO axios** (CVE vulnerability) |

## Project Structure (per demo)

```
zeroj-usecases/
├── CLAUDE.md                     ← this file (shared NFRs)
├── <usecase-name>/
│   ├── build.gradle              # Spring Boot + zeroj + frontend tasks
│   ├── settings.gradle
│   ├── src/main/java/            # Spring Boot backend
│   ├── src/main/resources/
│   │   ├── application.yml       # Config (network, mnemonic, etc.)
│   │   └── static/               # Built frontend output (Vite → here)
│   ├── src/test/java/            # JUnit + E2E tests
│   └── frontend/                 # Svelte 5 + Vite
│       ├── src/
│       ├── package.json
│       ├── vite.config.ts
│       └── svelte.config.js
```

## Build Commands

```bash
# Backend only
./gradlew build

# Full build (frontend + backend in one jar)
./gradlew build -PwithFrontend

# Run
java -jar build/libs/<usecase>.jar

# Dev mode (backend)
./gradlew bootRun

# Dev mode (frontend)
cd frontend && npm run dev
```

## Frontend-in-JAR Pattern

Vite builds to `src/main/resources/static/`. Spring Boot serves static files automatically.
Frontend build is conditional on `-PwithFrontend` Gradle property.

## Network Configuration

```yaml
# application.yml
cardano:
  network: yaci  # or: preprod
  yaci:
    base-url: http://localhost:8080/api/v1/
    admin-url: http://localhost:10000
  preprod:
    blockfrost-url: https://cardano-preprod.blockfrost.io/api/v0
    blockfrost-project-id: ${BLOCKFROST_PROJECT_ID}
```

## Constraints

- **NO axios** — use native `fetch` API in all frontend code
- **NO circom/snarkjs** — use pure Java prover (zeroj-crypto)
- **Server-side tx building** — Cardano transactions built on backend
- **Client-side signing** — wallet signing via MeshJS (Preprod) or hardcoded mnemonic (Yaci)
- **GraalVM compatible** — avoid reflection-heavy patterns; add native-image config if needed
