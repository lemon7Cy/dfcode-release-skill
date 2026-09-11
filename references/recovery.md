# Recovery and Limits

## CI

- `outputDir/state/ci.json` binds configuration fingerprint, workflow commit, branch, draft tag and run ID. `status` and `wait` never dispatch. A failed workflow must be diagnosed before any paid rerun; do not silently choose another source commit.
- Set Windows public signing config before `prepare` when using the same machine through publication. Keep both notes files frozen through prepare/dispatch/collect. Changing paths or adding Windows fields later does not preserve the original fingerprint. For cross-machine local signing, transfer verified unsigned inputs and `reports/verify-ci.json` to a fresh output with a local config; do not rewrite or reuse Mac CI state as Windows publication state.
- `dispatchPending: true` means an API call may have reached GitHub before the local record captured its run ID. Inspect `gh run list --repo BUILD_REPO --branch BRANCH --json databaseId,headSha,event,createdAt`; match the exact workflow commit and dispatch time, then record that one ID in the local state. Do not call dispatch again while uncertain.
- Existing state and branch conflicts stop instead of force-pushing. For a proven template fix, retain the failed evidence, use a new config/output/workspace, and set `attempt: 2` (then 3 if actually needed) with the same version and source pins. This suffixes only the tooling branch/internal draft tag, not the product version or upstream tag. Review the fix before another paid run; do not retry indefinitely or reset an unrelated checkout.
- A partial download is retained on digest mismatch. Quarantine only that known partial file and download it again; never accept size-only validation or skip a missing GitHub digest.
- Actions Artifacts quota failures do not require deleting anyone's caches. This workflow has no artifact actions and uses a pre-existing internal draft Release. CI minutes, budgets and authentication still matter; no automatic billing changes.

## Local Mac

The Mac driver records notarization IDs separately from the bytes it submits. Resume with unchanged config/inputs and `--resume`; Accepted submissions are not submitted again. If interruption occurred during upload before an ID was persisted, inspect recent notarytool history and match the filename and submission hash before resubmitting. Never print keychain passwords or API key material.

An input Engine manifest may describe the binary before CI ad-hoc signing. Only normalize that field after verifying GitHub asset digest, CI source/run evidence, complete original App ad-hoc signature, and the staged skills tree. Record old/new hash, sign Engine, update its hash again, and verify it remains unchanged during bundle signing. A random mismatch outside this evidence chain is a blocker, not a normalization opportunity.

Do not re-sign an existing failed staging bundle blindly: an ignored-filter bug may have signed ordinary binary resources. Re-extract the verified source archive into a new owned staging directory and preserve the failed report. Never relax nested verification, Team checks, entitlements or final-byte hashes merely to get a green result.

The Mac code is intended for the DFCode Studio packaging contract verified in historical 0.2.26. Future dependency updates, architecture changes or manifest schema revisions require inspection and focused test adaptation. Treat missing expected scripts or changed signing APIs as explicit compatibility blockers.

## Local Windows

`outputDir/reports/windows-state.json` records stage evidence and the inner PE signing journal. The NSIS signing hook has a separate journal under `outputDir/.work.noindex/windows/signing`. Resume with `windows-release.cjs --config ... --sign --execute --resume` or the shared `release.cjs sign --execute --resume`, using unchanged config, both notes files and original input. A finalized resume verifies the final report and file hashes; it does not sign again.

Every paid sign request first records intent and a detached copy. If a request times out or its outcome is unresolved, preserve its journal and detached bytes. Resume may accept an already verified signature but must not automatically issue that request again. Inspect the provider result and matching bytes before deciding recovery. Missing detached files, unexpected signatures or altered committed output stop the operation. A new output directory does not authorize repeating an unresolved paid request.

An interrupted NSIS build may already have signed its uninstaller or installer. Preserve the hook journal and outputs; do not automatically rebuild or re-sign while incomplete or ambiguous. A lock requires checking its recorded process before archiving a proven stale lock. Do not remove locks belonging to a live process.

Original extracted input, staged payload and final output hashes are rechecked during resume. Changed source/config/notes require a fresh config/output and new delivery evidence. Keep the immutable CI archive and receipt; never reset prior state to bypass its binding. Partial metadata output also remains for inspection and must not be published. Notes changes are not a supported reason to invoke resume over an existing signed release.

Windows currently supports the inspected `electron-builder`/`app-builder-lib` 26.15.3 packaging API and non-solid NSIS uninstaller format. Unknown source packaging settings or changed dependency versions require review and focused tests. Preserve installation scope from the source config; do not silently add all-users installation behavior. A final static report is separate from clean installation and actual OTA acceptance.

## Cleanup

On Mac, expanded `.app` bundles are temporary, not a second installation. Use `.work.noindex` from the outset. After verified final ZIP/DMG delivery, unregister and Trash only the exact generated expanded apps; check they are not running/open. Do not delete the release ZIPs, signing reports, credentials, source checkout or user's app data. Reports may retain historical staging paths after cleanup; the final app is recoverable from the retained signed ZIP. These unregister/Trash instructions apply only to Mac.

Do not enable/disable Gatekeeper, kill Finder/Dock, rebuild system registration databases, or reopen the application to refresh search results. Inspect source/version if the installed app changes concurrently and report the observed state without undoing the user's update.

Windows does not automatically remove unsigned inputs, extracted payloads, signing staging, hook journals or delivery evidence. Retain them for recovery and audit; any later cleanup must be scoped to verified task-owned paths and must preserve credentials, installed applications and user data.
