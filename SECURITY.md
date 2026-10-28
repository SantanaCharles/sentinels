# Security policy

## Reporting a vulnerability in Sentinels

Do not open a public issue. Use GitHub's **Private vulnerability reporting** (the *Security* tab →
*Report a vulnerability*) or write to Smart Code Tecnologia's contact email at
https://smartcodetecnologia.com.br.

Include the version (`sentinels version`), the install method (systemd or Docker) and steps to
reproduce. We respond within 5 business days and agree on disclosure after the fix.

## Supported versions

Only the latest version receives security fixes.

## Project guarantees

- The agent is **read-only**: it does not change containers, system files or firewall rules. On a
  Docker install it talks to the Docker API through a proxy that blocks any write.
- The **emergency alert feed** is signed with Ed25519; the binary rejects a feed without a valid
  signature, and the feed can only add alerts, never remove the embedded ones.
- Releases ship a `checksums.txt` (SHA-256); `install.sh` refuses a file that does not match.
- Text coming from logs is treated as untrusted data in alerts, reports, vault notes and AI
  prompts. The AI does not run actions.
- Secrets only via environment variables; the values of container variables are not read.

## Feed signing key

The private key stays with the maintainers, outside the repository. If it is compromised: generate a
new pair (`go run ./cmd/feedsign keygen`), update `FeedPublicKey` in `internal/intel/signing.go`,
sign the feed again and publish a release — old agents start rejecting the feed and keep using the
embedded list until they are updated.
