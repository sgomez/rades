# Roadmap

Milestones from easiest to hardest (ADR-0001). Each one lists the items it closes by their ID in [the standards inventory](research/ades-standards-inventory.md#inventory-checklist), which holds the description and the source of each; every ID lands in exactly one milestone or in [Not planned](#not-planned).

## Done means

A format item is done when:

1. it signs in two phases (O-01) with reproducible output (B-36);
2. DSS validates it at its level with `TOTAL_PASSED` (C-13);
3. the ETSI Signatures Conformance Checker reports no error (C-12);
4. the cases of its ETSI test specification are covered, when there is one;
5. AutoFirma's signatures of the same kind verify in rades, and rades' in AutoFirma (C-14), when AutoFirma has the format.

## Milestones

### M0. Harness

The oracles and the API shape, before any format: a generated test PKI, DSS in the CI, the conformance checker and the AutoFirma round-trip.

With no format yet, each oracle is proven on a third-party signature and a tampered copy; every format then exercises the oracles, and B-36, through [Done means](#done-means).

O-01, B-36, C-12, C-13, C-14

### M1. CMS and CAdES B-B

DER and CMS, the first signed attributes, and the hashes and signature algorithms everything else reuses.

B-01, B-02, B-03, B-04, F-01, F-02, F-03, F-53, A-01, A-02, A-04, A-05, A-06, A-13, C-01, C-03

A-06 covers P-256, P-384 and P-521 here; brainpool and FRP256v1 come with M13, where validating foreign signatures needs them.

### M2. Signed attributes and policies (EPES)

What the Spanish sites ask for: the AGE policy, commitment types, roles and place.

B-05, B-06, B-07, B-08, B-09, F-07, F-52

B-08 and F-52 (CAdES part) are done: rFirma can move CAdES `sign` under the AGE policy, without a time stamp, to rades. The rest of CAdES waits for M3 and M4. F-52 is rechecked for PAdES in M8 and XAdES in M11.

### M3. Time stamps and B-T

The RFC 3161 client, shared by every format from here on.

B-11, B-12, B-13, F-04, O-11

### M4. CAdES co-signatures and countersignatures

O-02, O-07

### M5. ASiC with CAdES

The ZIP container and its manifests. rFirma can move CAdES-ASiC-S here.

B-32, B-33, F-40, F-43, F-44, F-45, O-06, C-09, C-10

F-40 covers B-B and B-T here; B-LT and B-LTA come with M14 and M15.

### M6. JAdES

JWS with AdES headers. Public bodies must accept it from 2027-02-23 (CIR 2026/248).

B-29, B-30, B-31, F-29, F-30, F-31, F-32, F-33, F-34, F-38, F-39, O-04, O-10, A-07, C-11

### M7. PDF engine and invisible PAdES B-B

First wall: a PDF parser and incremental writer that survive real-world files.

B-23, B-24, F-19, F-25, O-05, O-17, O-19, O-20, C-07, C-08

### M8. Visible PAdES, certification and PDF safety

The appearance, DocMDP, encrypted PDFs and the checks before co-signing. rFirma can move PAdES here, once M9 is done for the sites that ask for a time stamp.

O-16, O-18, O-21, O-22, O-24, B-28, F-26

### M9. PAdES B-T

F-20, F-21, F-28, B-26

### M10. XML engine

Second wall: a parser that keeps what C14N needs, the C14N variants and the transforms.

B-19, B-20, B-21, B-22

### M11. XAdES B-B and B-T

Every packaging, co-signatures and countersignatures.

F-09, F-10, F-11, F-12, F-13, F-14, O-03, O-08, O-09, C-05, C-06

### M12. FacturaE and ASiC with XAdES

rFirma can move XAdES, FacturaE and XAdES-ASiC-S here.

F-50, F-41, F-42

### M13. Basic validation

Validating at the current time without long-term material: what rFirma needs to show a document's signatures. **With M13, rFirma no longer needs the Java bridge for signing or reading signatures.**

V-01, V-02, V-05, V-06, V-07, V-08, V-16, V-28, B-17, B-18, A-03

### M14. Revocation and B-LT

Third wall: OCSP and CRL clients, and validation material in every format.

B-14, B-15, B-16, B-25, F-05, F-15, F-22, F-35, O-12, O-15

### M15. B-LTA and archive time stamps

CAdES `archive-time-stamp-v3` is the hardest structure of all formats; PAdES is the easiest LTA.

F-06, F-16, F-17, F-23, F-36, O-13, O-14

### M16. Long-term validation

EN 319 102-1 with time, past validation, POE, the constraints model and the ETSI validation report.

V-03, V-04, V-09, V-10, V-11, V-12, V-13, V-14, V-15, V-17, V-18, V-29, V-30, A-12

### M17. Trusted lists and qualified status

What turns "valid" into "qualified": LOTL, national lists, QCStatements and the legal validation profile of CIR 2025/1945.

V-19, V-20, V-21, V-22, V-23, V-24, V-25, V-26, V-27

### M18. Legacy forms

Validating and augmenting what is already out there: TS 101 733/903, PAdES Basic, TS 103 17x (must validate until 2028-02-23), the extended and deprecated forms, and long-term FacturaE (XAdES-X-L).

L-01, L-02, L-03, L-04, L-05, L-06, L-07, L-08, F-08, F-18, F-37, F-51, A-08, C-02, C-04

### M19. Post-quantum and newer algorithms

TS 119 312 V2.1.1 says verifiers "shall support" ML-DSA and SLH-DSA.

A-09, A-10, A-11, B-27

### M20. Remote signing

A CSC client as one more signer behind the two-phase API.

R-01

## Ongoing

C-15: ETSI Plugtests, whenever one covers a format already done.

## Not planned

| IDs | Why |
| --- | --- |
| F-24 | PDF 2.0 in PAdES is a draft (EN 319 142-1 V1.3.0); revisit once published. |
| F-27 | XAdES inside PDF (XFA) is deprecated by ISO 32000-2 and nobody in our scope uses it. |
| F-46, F-47, F-48, B-34 | Evidence records are a preservation-service concern, not a signer's. |
| F-49 | CB-AdES (CBOR/COSE) is new (2026-03) and has no consumer yet. |
| B-10 | Machine-readable policies: Spanish policies are PDFs identified by hash; nothing parses them. |
| B-35 | S/MIME wrapping is informative and outside signing documents. |
| O-23 | Batch signing is orchestration over O-01 and belongs to the consumer (rFirma). |
| R-02 | Remote validation is a service protocol; rades validates locally. |
