# BSAAP forensic log verification

.NET 9 library and xUnit tests for the ISDFS 2027 synthetic-payment research prototype.

```sh
dotnet build
dotnet test
```

## Evidence protocol

- Provision distinct named ECDSA P-256 keys for gateways, witnesses and auditors using a trusted registry. Grant explicit gateway, log and corridor scopes. Gateway keys identify one gateway, and a signer ID may differ from its gateway ID. IDs use ordinal, case-sensitive matching. Checkpoints cover the entire scoped log and epoch, while entries, obligations, witnesses and challenges also require corridor authorization when evaluated for an obligation.
- Use version 2 obligations. A gateway may sign its own obligation. A counterparty obligation requires a signature from a key authorized for the target gateway, log and corridor. The acknowledgment binds the issuer's identity, obligation fields and exact issuer signature.
- After the publication deadline, the auditor draws a fresh 32-byte nonce with a cryptographically secure random generator, signs a challenge for that exact signed obligation and log epoch, and sends the challenge to the gateway. The gateway must sign its current complete head in response, embedding the digest of the signed challenge. An independent witness signs the exact checkpoint digest and gateway signature hash with its observation time. Verify during the challenge window using a trusted clock. Times are Unix seconds, and a challenge issued exactly at the deadline is insufficient.
- Supply the full ordered snapshot and all available trusted checkpoint history for the audited log epoch. The verifier checks leaf indices, entry signatures and scope, tree size and reconstructed root. Two authorized gateway signatures over conflicting roots at the same position prove equivocation. A smaller signed root that differs from the authenticated prefix of a larger head proves inconsistency. Compatible heads presented in reverse size order yield an inconclusive result without independent evidence of their order.
- Use the version 2 canonical encoding for every signed artifact. It uses a distinct domain string per artifact, strictly encoded UTF-8 with BinaryWriter length prefixes, little-endian integers, .NET Guid byte ordering, and length-prefixed variable byte fields. Sign with SHA-256 and 64-byte IEEE P1363 ECDSA signatures. The previous signing format is incompatible. RFC 9162 specifies the Merkle computation. The signed evidence format is specific to BSAAP.

## Independent review

| Starter defect | Correction |
| --- | --- |
| The Merkle domain prefix was assigned to the array, so the project failed to compile. The original root test only checked digest length. | Fixed leaf and node prefixes and the overflow-prone split calculation. Tests compare exact roots for sizes 0 through 8 against published reference vectors. |
| Delimiter-separated signatures admitted ambiguous encodings. The registry accepted unchecked curves, mutable keys, overwriteable identities and implicit wildcard scopes. | Versioned, domain-separated encoding. The registry validates P-256 SPKI, rejects trailing data and duplicate keys or IDs, isolates buffers and requires explicit grants. |
| Snapshot count narrowed from 64 bits, and leaf authorization confusingly used signer ID as gateway ID. | Verify count without narrowing, bind each leaf to the audited owner, log and epoch, authenticate contents, and recompute the root. Capture caller-owned evidence before making decisions. |
| Late witnessing could make an old checkpoint look fresh. Counterparty acknowledgment did not bind the exact issuer artifact. | Require a scoped post-deadline auditor challenge and exact checkpoint witnessing. Bind signed obligations, issuer authentication and target acknowledgment. |
| Equivocation checking omitted the current head unless the caller added it. It also accepted unrelated findings in a targeted audit. The append-only path could accept substituted signature arguments and compare across epochs. | Check the current head against same-epoch history, authenticate all heads used for a finding, and match append-only arguments to independently authenticated snapshots. Scope failures report unauthorized evidence. |
| First-match payload checks could make contradictory duplicates depend on leaf order. | Evaluate all matches. Mixed payloads are inconclusive. |

The Merkle fixtures come from the [transparency-dev reference vectors](https://github.com/transparency-dev/merkle/blob/main/testonly/constants.go). RFC 9162 retains the SHA-256 Merkle Tree Hash used by those fixtures. [RFC 9162 §2.1.3](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.3)

## Readiness and limitations

- A logging omission verdict is conditional on the gateway's challenge response representing its complete current log view. The auditor and witness must have independent custody and trustworthy clocks. Distinct keys enforce cryptographic role separation. Organizational independence, collusion resistance, challenge issuance and clock discipline are deployment assumptions.
- The engine evaluates the supplied history. An undisclosed split view requires checkpoint collection or gossip to become detectable. The prototype does not persist history, manage keys or revocation, enforce challenge issuance and retention, or establish continuity across epochs. Keep caller-owned evidence stable during capture, and enforce input limits before parsing or invoking the library.
- `Compliant` means the expected payload is present in the authenticated challenged snapshot. A later snapshot cannot establish publication by the deadline. An omission is a finding about the challenged log view, and a signed record does not independently prove that a payment event took place.
- This is a full-snapshot verification prototype. Compact inclusion and consistency proofs, external evidence acquisition, production integration and performance evaluation remain outside this implementation.
