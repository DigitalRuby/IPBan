# AGENTS_INDEX.md

Quick map of the IPBan repository for AI agents.

## Build basics

- Solution: `IPBan.sln`. Target framework `net10.0`. `IPBan/global.json` pins the SDK.
- No central package management. Versions live in each `.csproj`.
- IPBanCore is also consumed by `..\IPBanProSDK` and `..\IPBanPro` (IPBanPro.sln includes IPBanCore, IPBan and IPBanTests).

## Package policy

- Microsoft packages (Microsoft.Extensions.*, Microsoft.Data.Sqlite, System.*) stay on the **10.0.x** line. Don't move to 11.x yet.
- `System.CommandLine` follows the same train: 2.0.x = .NET 10, 3.x = .NET 11.
- Tests: NUnit 5, NUnit3TestAdapter 6, Microsoft.NET.Test.Sdk / Microsoft.TestPlatform.TestHost 18.x, coverlet.collector.

## Projects

| Project | Purpose |
|---|---|
| IPBanCore | Core library: firewall integration, log parsing, hosting (Windows service / systemd), SQLite, NLog |
| IPBan | Service / console host |
| IPBanClient | Client console |
| IPBanTests | NUnit tests for IPBanCore |

Other folders: `Recipes` (config recipes), `bucket` (Scoop manifest), `.github` / `azure-pipelines.yml` (CI).
