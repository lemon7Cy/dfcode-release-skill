# Implementation Validation

Initial skill implementation: 2026-09-10. This is a historical coverage record, not a promise that every future source/dependency revision is compatible.

- Skill frontmatter/reference validation passed.
- Generated Actions YAML passed actionlint v1.7.7 and shell syntax checks; multiple version/commit/channel renderings were tested. No new paid GitHub build was dispatched while creating the skill.
- Node tests cover config/pin/credential rejection, dry-run behavior, platform routing, Windows unimplemented signing, workflow safety, CI ZIP streaming, source/feed/manifest verification, nested Mac publication, notarization state reuse, ambiguous-submission stops, output protection and cleanup.
- The CI ZIP reader and mocked `collect` were replayed against existing real macOS/Windows unsigned Full OTA archives, the complete Windows signing input and the signed Mac Full OTA ZIP. GitHub calls in the collect simulation were mocked; original archives were read-only.
- Mac preflight was replayed on a freshly extracted historical 0.2.26 unsigned CI App in isolated `.work.noindex` staging. It verified 16 Mach-O files, 5 App bundles and 4 frameworks with complete ad-hoc signatures, source/architecture/skills checks, and correctly detected the stale pre-ad-hoc Engine manifest hash without changing it.
- No App, Engine server, mock OTA window, real upgrade, new signature or new Apple notarization submission was executed while testing this generalized skill. The earlier 0.2.26 live signing/notarization run supplies workflow experience; it does not by itself prove every new generic branch of the skill end-to-end.
- The preflight's generated expanded application was verified unused, unregistered or confirmed already absent from registration, and moved to Trash. Installed DFCode and user data were untouched.
- Windows sign/repackage/runtime acceptance is intentionally not implemented here. Windows user work should complete the contract in `windows-handoff.md`, add Windows-native tests, and run an authorized real release acceptance before marking that route ready.

Run all deterministic tests with `node scripts/test.cjs`. Mac tests use fixtures/mocks for mutating operations. The skill requires dependencies from the selected Studio checkout for real archive/signing execution, not a copied old `node_modules` directory.
