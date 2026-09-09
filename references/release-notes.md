# Release Notes From Actual Binaries

1. Download the previous release's small `BUILD-INFO` and `FULL-OTA-RELEASE-*.json` assets, or read `release.json` in its actual Full OTA ZIP. If the tag commit and manifest differ, use the manifest for shipped-code comparison and explain the distinction. Platform hotfixes may have different actual baselines despite the same version label.
2. Compare that Studio commit to the user's selected Studio commit. Compare the actual old Engine commit to the chosen new Engine commit and read package versions at both endpoints. Count endpoint net changes separately from merges, tests, docs and runtime code. Commit counts are not feature counts.
3. Read substantive implementation diffs and focused tests. Group user-visible changes, and distinguish new functionality, existing-function improvements and fixes. Squashed PR subjects often hide a large set of changes. Old release notes edited after a build do not retroactively make a feature part of the shipped old binary.
4. Produce a detailed GitHub document and a separate plain-text OTA summary no longer than 4000 JavaScript characters. Preserve actual limitations, platform differences and initiating-client behavior for Windows silent updates. Do not claim CDN/Range fixes from a progress-bar change, a whole feature from a renamed button, or GUI functionality from an Engine TUI-only change.
5. Record source pins, Engine version, CI URL, native signing status and actual verification categories. Never copy an older test count or say a mock UI test proves live OTA. A Windows input handoff is not a signed Windows release.

Historical calibration: 0.2.25 actually shipped Studio `02f6fac...` and Engine 3.3.16 `861e455...`; the selected 0.2.26 pair was Studio `5e1fe8d...` and Engine 3.3.18 `303382a...`. Full notes required twelve topic groups. These are historical examples, not defaults for future runs.

## Notes-only Revision

Changing prose does not require rebuilding/resigning the application. Preserve the signed DMG, App ZIP and blockmap byte hashes. Invoke the existing Studio `prepare-admin-full-ota-release.mjs` against original canonical artifacts into a **new** output directory with the revised notes, unchanged pins/signing metadata, then zip the new directory's contents. This script removes its output directory: never point it at inputs, source, user folders or the final delivery directory.

Verify only feed and release manifest changed, regenerate outer ZIP/checksums, and replace the existing upstream asset only for an explicitly requested correction. Keep a recoverable copy of the former ZIP and checksum list. Also update independent OTA notes and the Windows handoff; already-built unsigned inputs may retain historical short notes and must not be silently re-labelled as newly built.
