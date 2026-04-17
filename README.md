# nest-scan

A static analysis tool for NestJS codebases. Point it at a GitHub repo, and it gives you a security and code quality report — broken down by analyzer, with AI-powered explanations when you plug in a Gemini key.

Built because manually reviewing NestJS services for the same recurring issues (missing guards, raw SQL, no rate limiting, etc.) gets old fast.

---

## What it does

- Fetches your repo via the GitHub API (no cloning required)
- Runs 12+ static analyzers against your source code
- Maps out all your endpoints, controllers, and modules
- Optionally sends findings to Gemma AI for prioritization and fix suggestions
- Displays everything in a dashboard with severity breakdowns

## Analyzers

| Analyzer | What it checks |
|---|---|
| **AuthGuard** | Endpoints missing `@UseGuards()` |
| **IDOR** | Direct object references without ownership checks |
| **Injection** | SQL/NoSQL injection via raw queries or template strings |
| **MassAssignment** | DTOs or plain objects passed directly to Prisma/TypeORM |
| **SensitiveData** | Hardcoded secrets, exposed PII in responses |
| **Validation** | Missing `class-validator` pipes on request bodies |
| **TypeSafety** | `any` types, unsafe casts, missing return types |
| **Endpoint** | Full endpoint map (method, path, guards, params) |
| **Prisma** | Unsafe queries, missing `select`, raw SQL calls |
| **Module** | Module structure completeness (controller, service, spec) |
| **Pattern** | Anti-patterns like business logic in controllers |
| **CodeSmell** | Overly long files, nested callbacks, unused imports |
| **RateLimit** | Missing throttle decorators on public endpoints |

---

## Stack

**Backend** — NestJS 11, TypeScript  
**Frontend** — Next.js 15, React  
**AI** — Gemma 3 27B via Gemini API (`@google/generative-ai`)  
**Data** — GitHub REST API (no git clone)

---

## Getting started

### Prerequisites

- Node.js 18+
- A GitHub account (optionally, a Personal Access Token for private repos)
- A Gemini API key (optional, but unlocks AI review)

### 1. Clone the repo

```bash
git clone https://github.com/hamdanryuzz/nest-scan.git
cd nest-scan
```

### 2. Set up the backend

```bash
cd backend
npm install
```

Create a `.env` file:

```env
# Required
PORT=3001

# Optional — enables AI-powered code review
GEMINI_API_KEY=your_key_here
```

Start the dev server:

```bash
npm run start:dev
```

The API will be available at `http://localhost:3001`.

### 3. Set up the frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

---

## Usage

Enter a GitHub repo URL and branch in the dashboard, then hit **Scan**. For private repos, add your GitHub PAT in the input field — it's sent only to the backend and never stored.

```
https://github.com/your-org/your-nestjs-repo
```

The scan typically completes in 10–30 seconds depending on repo size.

---

## API

```
POST /scanner/scan
Content-Type: application/json

{
  "repoUrl": "https://github.com/owner/repo",
  "branch": "main",
  "pat": "ghp_optional_token"
}
```

Response includes:

```json
{
  "id": "scan-...",
  "summary": {
    "critical": 3,
    "warning": 11,
    "info": 5,
    "totalFiles": 42,
    "totalModules": 8,
    "totalEndpoints": 24,
    "scanDurationMs": 8312
  },
  "findings": [...],
  "endpoints": [...],
  "modules": [...],
  "aiReview": { ... }
}
```

---

## Project structure

```
nest-scan/
├── backend/
│   └── src/
│       └── scanner/
│           ├── analyzers/       # One file per analyzer
│           ├── ai/              # Gemma integration
│           ├── git/             # GitHub API fetching
│           ├── models/          # TypeScript interfaces
│           ├── scanner.service.ts
│           └── scanner.controller.ts
└── frontend/
    └── src/
        └── app/                 # Next.js app router
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Backend port (default: `3001`) |
| `GEMINI_API_KEY` | No | Enables AI review via Gemma 3 27B |

If `GEMINI_API_KEY` is not set, the tool still runs all static analyzers — AI review is just disabled.

---

## License

MIT
