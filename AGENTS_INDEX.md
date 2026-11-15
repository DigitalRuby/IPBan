# AGENTS_INDEX.md

Quick map of the IPBan repository for AI agents.

## Build basics

- Solution: `IPBan.sln`. Target framework `net10.0`. `IPBan/global.json` pins the SDK.
- No central package management. Versions live in each `.csproj`.

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

## JSON helpers (IPBanCore)

- `Core/Utility/JsonValueHelpers.cs` is the one place for safe ad hoc JSON reads and writes on `JsonElement`, `JsonNode` and `Utf8JsonReader`, plus `JsonSerializationHelper.TryParse*` / `ParseObjectOrNew`. Nothing in it throws for missing properties, wrong value kinds, json null, non-object receivers or invalid text. Use it instead of raw `GetProperty` / `GetString()` / `GetValue<T>()` / `JsonDocument.Parse` / `Enum.Parse`.
- The file is also compiled into IPBanPro projects that don't reference IPBanCore (linked `Compile` item, public types), so keep it self contained: no other IPBanCore types, no reflection, AOT/trim safe, `#nullable disable` at the top.
- Tests: `IPBanTests/IPBanJsonValueTests.cs`.
