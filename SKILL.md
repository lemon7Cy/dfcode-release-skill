---
name: dfcode-release
description: Build DFCode Studio installers and matching Full OTA ZIPs from user-selected Studio and Engine commits using a private GitHub staging repository and Release assets, then sign locally on Windows x64 or sign and notarize on macOS arm64. Use for DFCode release builds, signing handoffs, native signing, or OTA package delivery.
---

# DFCode Release

Input: two exact Studio/Engine commits, optionally a release version. Output: matching unsigned macOS arm64 and Windows x64 CI inputs on GitHub, plus the host platform's signed installer and matching Admin Full OTA ZIP. Mac arm64 uses local signing/notarization; Windows x64 uses local KeyLocker signing and NSIS repackaging. Production Admin publication and installing or upgrading the application are separate operations.

## Start

1. Read [configuration and commands](references/configuration.md). Resolve each supplied ref to a full commit in its intended repository. Do not substitute moving `main`, `feature/dev`, or a newer Engine tag after resolving.
2. The user's ordinary release request authorizes the build/sign/handoff stages they requested; announce the concrete version, pins, repository and platform route before execution. A question, audit or skill-development request does not authorize a paid CI build or signing run. The scripts require `--execute` for mutations.
3. With only two commits, `release.cjs init` reads the Engine version and proposes the Studio source version if newer than the latest stable release, otherwise the next stable patch. Honor an explicit user version. If no stable baseline exists, a prerelease is intended, or the chosen version already has another build, align the version instead of overwriting it.
4. Author full release notes and a <=4000-character OTA summary using [release notes rules](references/release-notes.md). Read the previous actual release manifests, not just its tag or the current old-version notes file. Do not invent changes or reuse stale verification claims.

## Execute in Order

Use the absolute path to this skill's `scripts/release.cjs`; run from any directory. Keep the generated config and artifacts outside the skill/repository. See configuration reference for the exact commands.

- `plan`: read-only review of pins, paths and native route.
- `prepare --execute`: new isolated Studio checkout, frozen dependency install, and a source-pinned workflow/notes commit on a local staging branch. Inspect the selected source's build scripts before executing them; the template assumes the current DFCode desktop packaging contract.
- `dispatch --execute`, then `wait`: push only the dedicated personal-build branch, create an internal draft Release and run GitHub Actions. Do not switch to upstream Actions or move source tags to work around an error.
- `collect --execute`: download and verify GitHub SHA-256 digests, run/source records and both Full OTA manifests/feed hashes. Preserve full `win-unpacked` signing input, not only an unsigned EXE.
- Notify the user that unsigned inputs are ready. Generate Windows handoff documentation with `windows-release.cjs --config ... --execute` even on Mac when delivering both platforms.
- `sign --execute [--resume]`: dispatch by actual local OS/architecture. On `darwin/arm64`, read [Mac signing](references/macos.md). On `win32/x64`, read [Windows signing](references/windows-handoff.md); the shared command supplies `--sign` to the Windows driver. Direct `windows-release.cjs --execute` still only writes the cross-platform handoff; native execution requires `--sign --execute`. Linux and Intel Mac stop at unsigned handoff.
- `publish --execute`: upload verified deliverables to the upstream GitHub Release, defaulting to a draft. Publishing the GitHub Release itself additionally requires the user's publication authorization and `--publish-release`; inspect upstream tag-triggered workflows first because creating a published tag can start them. Production Admin publication is never included.

## Required Invariants

- Defaults: source `wbz0429/dfcode-studio`, Engine `wbz0429/xingyuanshusuan-dfcode`, personal build repository `lemon7Cy/dfcode-studio`. Verify access and staging privacy every run. A private staging copy need not belong to GitHub's fork network.
- **Always use draft Release assets for CI transfer**, not `actions/upload-artifact` / `download-artifact`. The 500MB Actions artifact allowance is separate from Release storage; CI minutes/budgets still apply. Never fall back by clearing another user's artifacts or changing billing.
- Application source commit and workflow commit are different provenance fields. Version stamping and selected Engine source configuration are allowed packaging adjustments; runtime-source edits require a new explicit source decision.
- CI stays unsigned and receives no Apple or DigiCert signing material. Existing local keychain profiles are used for notarization; Windows uses the established KeyLocker setup through SMCTL `--simple`. Windows config contains only public certificate identifiers and tool settings. Never commit `.p8`, PFX/P12, keychain exports, API keys, tokens, passwords, local configs, or signing identities with private-key material.
- Freeze config and both notes files through CI prepare/dispatch/collect. Signing consumes the independent current notes, never stale text embedded in CI ZIPs. Windows signing state binds config and both notes hashes; changed signing notes require a fresh config/output and cannot reuse old signing state or bypass CI fingerprints.
- Local signing uses isolated `.work.noindex` staging. **Never launch a real or simulated OTA window by default**, copy to `/Applications`, quit the user's app, touch live user data, or exercise paid inference. Runtime/UI tests require explicit coordination and must be labelled separately from byte/signature checks.
- Sign Engine first and refresh its binary hash. On Mac exclude it from later bundle signing; for `@electron/osx-sign 1.3.3`, a single `ignore` callback is required because its array normalization loses array values. On Windows verify every inner PE, preserve approved valid Microsoft DLL signatures, and sign the generated uninstaller and final NSIS installer. Do not weaken manifest checks to bypass failures.
- Signatures change bytes. Rebuild final ZIP, blockmap, feed SHA-512/size and schema-v3 `release.json` from final bytes. On Mac verify DMG's `Applications -> /Applications` and equality of App contents in DMG and OTA ZIP. On Windows compare the final extracted payload to the signed staging copy and verify the embedded uninstaller.
- The inspected Windows packaging API is `electron-builder`/`app-builder-lib` 26.15.3, including its non-solid NSIS embedded uninstaller format. Dependency or source packaging drift requires evaluation. Installation scope is inherited from the selected source; this skill does not implement an all-users installation fix.
- Publicly distinguish build tests, native signature/notarization, runtime startup, clean-machine Gatekeeper and real OTA acceptance. A local `spctl` override on a security-disabled machine is not default-policy acceptance.

## Recovery and Delivery

Read [recovery and limits](references/recovery.md) on an interrupted run. Persist Actions run IDs and notarization submission IDs. Never automatically dispatch a second paid build or resubmit an upload whose ID may already exist. Fix a proven blocker with a bounded retry, preserving failed inputs and exact source pins.

Deliver the native signed installer, matching signed Full OTA ZIP, source record, checksums and verification report; include the upstream Release link only if that handoff was requested. Windows `status: finalized` records signing and static package checks, not installation or real OTA acceptance. Before finishing, verify the installed application was not touched. Mac cleanup unregisters and Trashes only skill-created expanded `.app` staging copies; retain final ZIP/DMG and evidence. Windows retains unsigned inputs, staging and signing directories for audit/recovery. Cleanup must not erase worktrees, keys, live data or user files.

For a documentation-only notes revision, preserve signed native payload/installer/blockmap bytes and signatures; regenerate only the feed, release manifest and outer Full OTA ZIP into a new staging directory, then replace a published asset only when the user requested that replacement. Update checksums and independent notes together. The Windows resume command is not a notes-revision command: changed notes require fresh config/output and new delivery evidence.

Implementation coverage and outstanding real installation/OTA acceptance are recorded in [validation](references/validation.md). Run `node scripts/test.cjs` from this skill to validate changes on either OS; it enumerates test files without shell-specific glob expansion.
