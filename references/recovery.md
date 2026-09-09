# Recovery and Limits

## CI

- `outputDir/state/ci.json` binds configuration fingerprint, workflow commit, branch, draft tag and run ID. `status` and `wait` never dispatch. A failed workflow must be diagnosed before any paid rerun; do not silently choose another source commit.
- `dispatchPending: true` means an API call may have reached GitHub before the local record captured its run ID. Inspect `gh run list --repo BUILD_REPO --branch BRANCH --json databaseId,headSha,event,createdAt`; match the exact workflow commit and dispatch time, then record that one ID in the local state. Do not call dispatch again while uncertain.
- Existing state and branch conflicts stop instead of force-pushing. For a proven template fix, retain the failed evidence, use a new config/output/workspace, and set `attempt: 2` (then 3 if actually needed) with the same version and source pins. This suffixes only the tooling branch/internal draft tag, not the product version or upstream tag. Review the fix before another paid run; do not retry indefinitely or reset an unrelated checkout.
- A partial download is retained on digest mismatch. Quarantine only that known partial file and download it again; never accept size-only validation or skip a missing GitHub digest.
- Actions Artifacts quota failures do not require deleting anyone's caches. This workflow has no artifact actions and uses a pre-existing internal draft Release. CI minutes, budgets and authentication still matter; no automatic billing changes.

## Local Mac

The Mac driver records notarization IDs separately from the bytes it submits. Resume with unchanged config/inputs and `--resume`; Accepted submissions are not submitted again. If interruption occurred during upload before an ID was persisted, inspect recent notarytool history and match the filename and submission hash before resubmitting. Never print keychain passwords or API key material.

An input Engine manifest may describe the binary before CI ad-hoc signing. Only normalize that field after verifying GitHub asset digest, CI source/run evidence, complete original App ad-hoc signature, and the staged skills tree. Record old/new hash, sign Engine, update its hash again, and verify it remains unchanged during bundle signing. A random mismatch outside this evidence chain is a blocker, not a normalization opportunity.

Do not re-sign an existing failed staging bundle blindly: an ignored-filter bug may have signed ordinary binary resources. Re-extract the verified source archive into a new owned staging directory and preserve the failed report. Never relax nested verification, Team checks, entitlements or final-byte hashes merely to get a green result.

The current code is intended for the DFCode Studio packaging contract verified in 0.2.26. Future dependency updates, architecture changes or manifest schema revisions require inspection and focused test adaptation. Treat missing expected scripts, changed signing APIs or Windows schema drift as explicit compatibility blockers.

## Cleanup

Expanded apps are temporary, not a second installation. Use `.work.noindex` from the outset. After verified final ZIP/DMG delivery, unregister and Trash only the exact generated expanded apps; check they are not running/open. Do not delete the release ZIPs, signing reports, credentials, source checkout or user's app data. Reports may retain historical staging paths after cleanup; the final app is recoverable from the retained signed ZIP.

Do not enable/disable Gatekeeper, kill Finder/Dock, rebuild system registration databases, or reopen the application to refresh search results. Inspect source/version if the installed app changes concurrently and report the observed state without undoing the user's update.
