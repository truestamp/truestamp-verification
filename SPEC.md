<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp proof specification

**Status:** outline. The sections below name what this document will define; none of it
is normative yet.

This document defines a Truestamp proof and how to verify it. It is the only normative
document in this repository. The files under `spec/` and `vectors/` are its data, and
`MANIFEST.sha256` holds their digests; a citation of this document names the commit and
the manifest digest.

## 1. Introduction

Scope and audience: anyone, human or agent, who writes or audits a verifier. What a proof
establishes (that data existed, that it is unchanged, and the submission window in which
it was submitted) and what it does not (when the data was created, or who wrote it).

## 2. Conventions

The BCP 14 key words, the notation, and the rules every member follows: closed objects,
absent rather than null, full-string patterns, and the pattern classes and encodings.

## 3. The proof document

### 3.1 The envelope
### 3.2 Members of `proof`
### 3.3 Block node, key events and genesis
### 3.4 Commitments
### 3.5 Entropy objects
### 3.6 Layouts by type
### 3.7 Value classes
### 3.8 Size

## 4. The byte-prefix registry

### 4.1 The rule
### 4.2 Layout
### 4.3 The table
### 4.4 Beacon draws

## 5. Merkle trees and inclusion proofs

The tree of RFC 9162 section 2.1 over entries sorted by key; an inclusion proof as the
leaf index, the tree size and the audit path, verified as RFC 9162 section 2.1.3.2 does;
and the committed leaf count that a proof's tree size is checked against. The known
answers are truestamp-merkle-elixir's `vectors/merkle.json`.

## 6. Signing

### 6.1 The rule
### 6.2 Strict verification
### 6.3 Worked example
### 6.4 The environment marker

## 7. Constructions

### 7.1 What it is, and who it is for
### 7.2 Modes
### 7.3 The text
### 7.4 The agent-sufficiency acceptance test

## 8. Verifier roles

Truestamp's own verifier uses its key chain and fails closed. An external verifier uses
the pinned keyring by default, which the keyring downloaded from www.truestamp.com
replaces online, and runs without a keyring only when asked, saying so.

## 9. What a verifier pins

The keys, literals, networks, sources and constants a verifier holds as its trust policy,
each published as a file under `spec/`.

## 10. The verification algorithm

### 10.1 Parsing
### 10.2 Steps
### 10.3 Links and the key-event row
### 10.4 Chain and source reads
### 10.5 Verdict and report
### 10.6 Declare and verify

## 11. The submission window

How the submitted-after and submitted-before edges are drawn from values the verifier
recomputes and from the chain and source reads it makes.

## 12. Reason codes and exit codes

## 13. Conformance

The cases in `vectors/cases.json`, what each asserts, and the fixtures every verifier
passes.
