# Scoop TODO for `ipban.json`

## Must do before first real Scoop release

- [ ] Decide where the Scoop manifest will live:
  - **This repo** using `bucket/ipban.json`, or
  - a dedicated bucket repo such as `DigitalRuby/scoop-ipban`, or
  - the official Scoop `Extras` bucket.
- [ ] If you keep the manifest in **this repo**, document install commands for users:
  - `scoop bucket add ipban https://github.com/DigitalRuby/IPBan`
  - `scoop install -g ipban`
- [ ] Enable GitHub Actions write access:
  - Repo Settings -> Actions -> General -> Workflow permissions -> **Read and write permissions**
- [ ] Decide which branch the workflow should push to.
  - Current workflow checks out `master`.
  - If the repo default branch is not `master`, update `.github/workflows/update-scoop-manifest.yml`.
  - If releases are made from `release-*` branches, decide whether the workflow should still push the manifest to `master` or to the release branch.
- [ ] Decide whether you want to keep **32-bit Windows** support in Scoop.
  - Current manifest and workflow expect both `win-x64` and `win-x86` release assets.
  - If you do **not** want 32-bit Scoop support, remove the `32bit` block from `bucket/ipban.json` and update the workflow accordingly.

## Release asset requirements

- [ ] Make sure GitHub Releases publish a Windows x64 zip named like:
  - `IPBan-Windows-x64_4.0.0.zip`
- [ ] If keeping 32-bit support, also publish:
  - `IPBan-Windows-x86_4.0.0.zip`
- [ ] Make sure release tags are compatible with the manifest.
  - `4.0.0` works.
  - `v4.0.0` also works because the workflow strips the leading `v` before writing the manifest version.
- [ ] Verify `IPBan/CreatePackage.ps1` is the script used to generate release zips.
  - It now emits dot-versioned zip names that match Scoop expectations.

## First release steps

- [ ] Create a real GitHub Release with the Windows zip assets attached.
- [ ] Wait for `.github/workflows/update-scoop-manifest.yml` to run.
- [ ] Confirm the workflow updates `bucket/ipban.json` with:
  - the new `version`
  - the real x64 hash
  - the real x86 hash, if applicable
- [ ] Remove or replace the placeholder hashes only through the release workflow or by manual update.
  - Current hashes in `bucket/ipban.json` are placeholders and will not install successfully until updated.

## Local validation after first release

- [ ] Test from a clean admin PowerShell prompt:
  - `scoop bucket add ipban https://github.com/DigitalRuby/IPBan`
  - `scoop install -g ipban`
- [ ] Confirm Scoop persists these files across update/reinstall:
  - `ipban.config`
  - `ipban.override.config`
  - `ipban.sqlite`
  - `nlog.config`
- [ ] Confirm the service is created successfully:
  - `Get-Service IPBan`
- [ ] Confirm the binary path points to the Scoop-installed version.
- [ ] Confirm the service starts:
  - `Start-Service IPBan`
- [ ] Confirm uninstall cleans up the service:
  - `scoop uninstall ipban`
  - `Get-Service IPBan` should no longer find the service
- [ ] Confirm update preserves persisted files:
  - install one version
  - modify `ipban.config`
  - update to the next version
  - verify config and sqlite were preserved

## Documentation tasks

- [ ] Add Scoop install instructions to `README.md`.
- [ ] Document that IPBan requires an **elevated** PowerShell session and should be installed globally with `-g`.
- [ ] Document that the Scoop package registers a Windows service.
- [ ] Document where users should edit config when installed by Scoop:
  - Scoop persisted config path, surfaced via `$persist_dir\ipban.config`

## Optional but recommended

- [ ] Submit `ipban.json` to the official Scoop `Extras` bucket for broader discoverability.
- [ ] If you submit to `Extras`, decide whether to keep this repo-hosted bucket too.
- [ ] Consider adding CI validation for the manifest itself:
  - JSON validity
  - URLs resolve
  - assets exist for current release
- [ ] Consider hardening the workflow for missing x86 assets.
  - Current workflow only skips when x64 is missing.
  - If x86 is missing but still referenced, the workflow may fail or write bad values.
- [ ] Consider whether the Scoop `post_install` should auto-start the service or only register it.
  - Current manifest registers the service and prints a message to start it.

## Current known caveats

- `bucket/ipban.json` currently contains placeholder SHA256 hashes.
- `.github/workflows/update-scoop-manifest.yml` currently pushes to `master`.
- The workflow currently assumes both x64 and x86 assets exist.
- Scoop installation should be tested specifically with service creation, uninstall, reinstall, and upgrade paths.
