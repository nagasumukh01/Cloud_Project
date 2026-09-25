# Prior-Art Search Checklist

**Status: NOT PERFORMED.** This file specifies the search that would have to be completed before
*any* novelty, originality, or patentability statement could responsibly be made about this
project. Nothing in this repository currently makes such a statement, and nothing should until
every box below is ticked and the findings written up.

## Why this file exists

An agent or author can very easily produce a confident-sounding "our novel mechanism is the first
to…" sentence. Such a sentence is unverifiable without a systematic search, and in a patent context
it can be actively harmful. This checklist replaces the claim with the procedure.

## 1. Academic literature

| Source | Coverage | Done? |
|---|---|---|
| IEEE Xplore | cloud verification, BFT inference, spot-checking | ☐ |
| ACM Digital Library | distributed systems, trust/reputation systems | ☐ |
| USENIX (OSDI, NSDI, Security, ATC) | systems + security venues | ☐ |
| arXiv (cs.CR, cs.DC, cs.LG) | preprints, zkML | ☐ |
| Springer LNCS / Elsevier FGCS, JPDC | cloud computing journals | ☐ |
| Google Scholar (forward citation chasing) | follow-ups to key hits | ☐ |

Suggested query seeds (to be logged with dates and hit counts):

- `verifiable machine learning inference untrusted cloud worker`
- `adaptive redundancy replication verification cost distributed computing`
- `reputation based spot checking volunteer computing BOINC`
- `risk adaptive verification policy trust score scheduler`
- `zkML SNARK proof of inference cost`
- `trusted execution environment ML inference attestation`
- `Byzantine fault tolerant machine learning inference serving`
- `anomaly detection malicious worker cloud task scheduling`
- `signed inference result provenance model version binding`
- `contextual bandit verification budget allocation`

## 2. Patent databases

| Database | Scope | Done? |
|---|---|---|
| Google Patents | full-text, worldwide | ☐ |
| Espacenet (EPO) | worldwide, family view | ☐ |
| USPTO Patent Full-Text (PatFT/AppFT) | US grants + applications | ☐ |
| WIPO PATENTSCOPE | PCT applications | ☐ |
| Indian Patent Advanced Search (InPASS) | IN filings | ☐ |

Classification codes to sweep (CPC):

- `G06F 21/64` — integrity of data/files
- `G06F 21/57` — platform integrity / attestation
- `H04L 9/32` — authentication, digital signatures
- `H04L 9/50` — distributed-ledger / hash-chain
- `G06N 20/00` — machine learning
- `G06F 9/50` — resource allocation in distributed systems
- `G06F 11/16` / `G06F 11/20` — redundancy and fault tolerance

## 3. Non-patent, non-academic prior art

- ☐ Open-source projects (GitHub/GitLab search: verifiable inference, worker attestation, adaptive replication)
- ☐ Industrial systems and their public documentation (BOINC, Folding@home, Golem, Bacalhau, Ritual, Modulus Labs, EZKL, Gensyn)
- ☐ Cloud-vendor whitepapers (confidential computing, Nitro Enclaves, Confidential Space)
- ☐ Standards and RFCs (RFC 6962 Certificate Transparency, RATS/EAT attestation, in-toto, SLSA, C2PA)
- ☐ Blog posts / technical talks, dated

## 4. Recording format

For each relevant hit, record: identifier (DOI / patent number / URL), date accessed, title,
assignee or authors, the specific claim or mechanism that overlaps, and an explicit statement of
**how this project differs, or whether it does not differ at all**. Negative findings — prior art
that already covers the mechanism — must be recorded with the same care as favourable ones.

## 5. Gate

Only after §1–§4 are complete may the project describe its contribution using comparative language
("to our knowledge, X has not been evaluated in combination with Y"), and even then scoped to the
search performed and dated. **Patentability is a legal determination and requires a qualified
patent attorney; it cannot be established by this checklist, by the authors, or by an AI agent.**

## 6. Current honest statement

> This project implements and evaluates a combination of established techniques — Ed25519-signed
> result envelopes, Merkle batch auditing, EWMA trust scoring, and risk-thresholded replication —
> applied to ML inference on untrusted workers. Each component is well known. No claim is made
> that the combination is novel; no prior-art search has been conducted.
