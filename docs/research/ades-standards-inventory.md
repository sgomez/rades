# AdES standards inventory

Inventory of everything a complete AdES library could have to implement, gathered to check the roadmap against. Researched 2026-10-21 from primary sources only. Every ETSI document is the latest **published** version on `etsi.org/deliver` at that date; drafts are flagged. "UNVERIFIED" marks claims not checked against the primary text.

Clause numbers point into the cited document. Reference-style links are at the end.

## 1. Legal layer

| Act | What it requires of a signature library | Source |
| --- | --- | --- |
| Regulation (EU) No 910/2014 (eIDAS), consolidated 2024-10-18 | Art. 26: an AdES is uniquely linked to and identifies the signatory, is created with data under the signatory's sole control, and detects any later change to the signed data. Art. 32(1): QES validation confirms points (a)–(h) (qualified certificate at signing time, issued by a QTSP, validation data matches, signatory data and pseudonym shown, QSCD used, integrity, Art. 26 met). Art. 32(2): the validator shows the correct result and lets the relying party detect security issues. Art. 33/34: qualified validation and preservation services. Art. 35–40 are the same for seals; Art. 41–42 cover (qualified) time stamps; Art. 22 covers trusted lists. | [eIDAS-cons] |
| Regulation (EU) 2024/1183 (eIDAS 2) | Adds **Art. 32a** (validating AdES based on qualified certificates: Art. 32(1) minus the QSCD point) and Art. 40a for seals. Turns the references to standards in Art. 32(3), 32a(3), 33(2) and 34(2) into implementing acts that give a presumption of compliance. Art. 26(2): the Commission had until 2026-05-21 to decide whether AdES needs reference standards. | [eIDAS-cons], [eIDAS2] |
| Commission Implementing Decision (EU) 2015/1506 | **Repealed** by 2026/248, Art. 5. It required public bodies to accept the XAdES, CAdES and PAdES baseline profiles TS 103 171 v2.1.1, TS 103 173 v2.2.1 and TS 103 172 v2.2.2 (clause 9 excepted) and the ASiC profile TS 103 174 v2.2.1. | [CID-2015-1506] |
| **Commission Implementing Regulation (EU) 2026/248** (2026-02-02, OJ 2026-02-03) | Formats public bodies must accept. **Annex I**, which applies from **2027-02-23** (Art. 6): XAdES EN 319 132-1 V1.3.1, CAdES EN 319 122-1 V1.3.1, PAdES EN 319 142-1 V1.2.1 and **JAdES TS 119 182-1 V1.2.1**, the last with one change: `x5c` **shall be present**, as a signed or unsigned header (TS 119 182-1 §5.1.8 itself makes it a signed header). Containers: EN 319 162-1 V1.1.1, plus EN 319 162-2 V1.1.1 for the ASiC-E CAdES additional container (§4.3.1). **Annex II**: the TS 103 171/172/173 baseline profiles at B, T or LT level (clause 9 excepted) and TS 103 174, for signatures created **before 2028-02-23**. Art. 2/4: other formats must be accepted when the TSP's Member State offers a free online validation method that meets the listed conditions. | [CIR-2026-248] |
| Commission Implementing Regulation (EU) 2025/1945 (2025-09-29) | Reference standards for validating QES/QESeal (Annex I) and AdES/AdESeal based on qualified certificates (Annex II): **TS 119 172-4 V1.1.1** and **TS 119 102-2 V1.4.1**, adapted. References become EN 319 102-1 V1.4.1 and TS 119 612 V2.3.1. Revocation is `eitherCheck`, with a freshness of at most 24 h for the signing certificate. REQ-4.3-02: validation applications shall comply with TS 119 101 V1.1.1. | [CIR-2025-1945] |
| Other 2025 implementing acts (context) | 2025/1943 (qualified certificates; cites EN 319 411-1 V1.5.1 and EN 319 401 V3.1.1), 2025/1946 (qualified preservation), 2025/1944 (QERDS) and 2025/2160 (non-qualified TSP risk management; **not** a formats act, despite secondary sources). | [CIR-2025-1943], [CIR-2025-1946], [CIR-2025-1944], [CIR-2025-2160] |

Consequence for the roadmap: under EU law, JAdES becomes a format public bodies must accept from 2027-02-23, and legacy TS 103 17x baseline signatures must keep validating until 2028-02-23.

## 2. Format standards and levels

### 2.1 Document versions

| Format | Part 1 (building blocks + baseline) | Part 2 (extended / additional) | Other parts |
| --- | --- | --- | --- |
| CAdES | EN 319 122-1 **V1.3.1 (2023-06)** [EN122-1] | EN 319 122-2 V1.1.1 (2016-04) [EN122-2] | TS 119 122-3 V1.2.1 (2026-08) ERS in CAdES [TS122-3] |
| XAdES | EN 319 132-1 **V1.3.1 (2024-07)** [EN132-1] | EN 319 132-2 V1.1.1 (2016-04) [EN132-2] | TS 119 132-3 V1.1.1 (2021-01) ERS in XAdES [TS132-3] |
| PAdES | EN 319 142-1 **V1.2.1 (2024-01)** [EN142-1]; **draft V1.3.0 (2026-08)**, in ENAP until 2026-11-09, adds PDF 2.0 [EN142-1-draft] | EN 319 142-2 **V1.2.1 (2025-07)** [EN142-2] | TS 119 142-3 V1.1.1 (2016-12) PAdES-DTS [TS142-3] |
| JAdES | TS 119 182-1 **V1.2.1 (2024-07)** [TS182-1] | none (no 119 182-2 folder) | none |
| ASiC | EN 319 162-1 V1.1.1 (2016-04) [EN162-1] | EN 319 162-2 V1.1.1 (2016-04) [EN162-2] | none |
| CB-AdES (CBOR/COSE) | TS 119 152-1 **V1.1.1 (2026-03)**, new [TS152-1] | none | none |

Common rule in every part 1: MD5 shall not be used; algorithms "should" follow TS 119 312 (CAdES §6.2.1, PAdES §6.2.1, ASiC §5.2.1).

### 2.2 CAdES baseline (EN 319 122-1 V1.3.1, §6.3 Table 1)

| Item | B-B | B-T | B-LT | B-LTA | Card. | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `SignedData.certificates` | shall | shall | shall | shall | 1 | includes the signing cert (a); full chain incl. trust anchors and TSA/OCSP/CRL certs (d) |
| `content-type` (=`id-data`) | shall | shall | shall | shall | 1 | §5.1.1 |
| `message-digest` | shall | shall | shall | shall | 1 | §5.1.2 |
| Service: protection of signing cert → `ESS signing-certificate` (SHA-1 only) **or** `ESS signing-certificate-v2` | shall | shall | shall | shall | 1 | §5.2.2; `issuerSerial` should be omitted (g) |
| `signing-time` | shall | shall | shall | shall | 1 | §5.2.1 |
| `commitment-type-indication` | may | may | may | may | 0..1 | §5.2.3 |
| Service: signed data type → `content-hints` and/or `mime-type` | should | should | should | should | 0..1 | §5.2.4, (t) |
| `signer-location` | may | may | may | may | 0..1 | §5.2.5 |
| `signer-attributes-v2` (claimed / certifiedAttributesV2 / signedAssertions) | may | may | may | may | 0..1 | §5.2.6.1; SAML variants §5.2.6.2–3 |
| `countersignature` | may | may | may | may | ≥0 | §5.2.7 |
| `content-time-stamp` | may | may | may | may | ≥0 | §5.2.8 |
| `signature-policy-identifier` | may | may | may | may | 0..1 | §5.2.9 |
| `signature-policy-store` | cond. | cond. | cond. | cond. | 0..1 | only with policy id carrying `sigPolicyHash` (k) |
| `content-reference`, `content-identifier` | may | may | may | may | 0..1 | §5.2.11–12 |
| `cms-algorithm-protection` (RFC 6211) | may | may | may | may | 0..1 | §5.2.13, note 8 |
| `signature-time-stamp` | * | **shall** | shall | shall | ≥1 | §5.3; DER (l); before revocation/expiry (m) |
| `certificate-values`, `complete-certificate-references`, `revocation-values`, `complete-revocation-references`, `attribute-certificate-references`, `attribute-revocation-references`, `CAdES-C-timestamp`, `time-stamped-certs-crls-references` | * | * | **shall not** | shall not | B-LT+: 0 | Annex A (legacy attributes) |
| Service: revocation values → `SignedData.crls.crl` (CRLs) / `SignedData.crls.other` (OCSP, RFC 5940) | * | * | **shall** | shall | 1 | (o)–(r) |
| `archive-time-stamp-v3` (+ `ats-hash-index-v3`) | * | * | * | **shall** | ≥1 | §5.5.2–5.5.3; all validation material first (s) |

Deprecated attributes still to be read: `other-signing-certificate`, `signer-attributes`, `archive-time-stamp` (v2), `long-term-validation`, `ats-hash-index` (Annex A.2). Annex B: alternative long-term mechanisms (ERS, see TS 119 122-3). §6.4: unsigned attributes added to legacy signatures shall follow the current document.

### 2.3 XAdES baseline (EN 319 132-1 V1.3.1, §6.3 Table 2)

Qualifying properties only by direct incorporation (a single `QualifyingProperties` in one `ds:Object`, no `QualifyingPropertiesReference`). Time stamps only RFC 3161/5816.

| Item | B-B | B-T | B-LT | B-LTA | Card. | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `ds:KeyInfo/X509Data` (signing cert) | shall | shall | shall | shall | 1 | (a)–(c) |
| `ds:SignedInfo/ds:CanonicalizationMethod` | shall | shall | shall | shall | 1 | C14N 1.0/1.1/exc, ± comments; "with comments" should not be used (d, e) |
| `ds:Reference` | shall | shall | shall | shall | ≥2 | |
| `ds:Reference/ds:Transforms` | may | may | may | may | 0..1 | allowed: base64, XPath, enveloped-signature, XSLT, XPath Filter 2.0, OOXML RelationshipTransform (g) |
| `SigningTime` | shall | shall | shall | shall | 1 | UTC (h) |
| `SigningCertificateV2` | shall | shall | shall | shall | 1 | no `URI` attribute (i); no `IssuerSerialV2` (j) |
| `SigningCertificate` (v1), `SignerRole` (v1), `SignatureProductionPlace` (v1) | shall not | shall not | shall not | shall not | 0 | |
| `DataObjectFormat` (+`MimeType` 1, `ObjectReference` 1, `Description`/`ObjectIdentifier`/`Encoding` 0..1) | cond. | cond. | cond. | cond. | ≥0 | one per signed object except SignedProperties; countersignature rule (k) |
| `SignerRoleV2` | may | may | may | may | 0..1 | §5.2.6 |
| `CommitmentTypeIndication` | may | may | may | may | ≥0 | §5.2.3 |
| `SignatureProductionPlaceV2` | may | may | may | may | 0..1 | §5.2.5 |
| `CounterSignature` | may | may | may | may | ≥0 | §5.2.7.2 (enveloped countersignature); detached countersignature via `ds:Reference/@Type` §5.2.7.1 |
| `AllDataObjectsTimeStamp`, `IndividualDataObjectsTimeStamp` | may | may | may | may | ≥0 | §5.2.8 |
| `SignaturePolicyIdentifier` | may | may | may | may | 0..1 | §5.2.9 |
| `SignaturePolicyStore` | cond. | cond. | cond. | cond. | 0..1 | (m) |
| `SignatureTimeStamp` | * (≥0) | **shall** | shall | shall | ≥1 | one time stamp each (n) |
| `CertificateValues`, `RevocationValues`, `AnyValidationData`, `AttrAuthoritiesCertValues`, `AttributeRevocationValues` | * | * | cond. | cond. | 0..1 / ≥0 | (p)–(w), (cc) |
| `CompleteCertificateRefsV2`, `CompleteRevocationRefs`, `AttributeCertificateRefsV2`, `AttributeRevocationRefs`, `SigAndRefsTimeStampV2`, `RefsOnlyTimeStampV2` | * | * | **shall not** | shall not | B-LT+: 0 | Annex A |
| v1 forms `CompleteCertificateRefs`, `AttributeCertificateRefs`, `SigAndRefsTimeStamp`, `RefsOnlyTimeStamp` | shall not | shall not | shall not | shall not | 0 | |
| Service: validation data of time stamps → `TimeStampValidationData` / inside the TST / `AnyValidationData` | * | * | **shall** | shall | | (x, y) |
| `ArchiveTimeStamp` in ns `v1.4.1#` | * | * | * | **shall** | ≥1 | §5.5.2; not-distributed and distributed digest computation §5.5.2.3–4 |
| `ArchiveTimeStamp` in ns `v1.3.2#` | shall not | shall not | shall not | shall not | 0 | legacy |
| `RenewedDigestsV2` | * | * | * | cond. | ≥0 | weak digests in a `ds:Manifest` (bb) |

Namespaces: `http://uri.etsi.org/01903/v1.3.2#` and `http://uri.etsi.org/01903/v1.4.1#` (Annex C).

### 2.4 PAdES baseline (EN 319 142-1 V1.2.1, §6.3 Table 1)

General (§4.1): a DER `SignedData` (CAdES per EN 319 122-1) in `/Contents`, **exactly one SignerInfo**; content is not encapsulated. CAdES attributes not listed below shall not be present (§6.3).

| Item | B-B | B-T | B-LT | B-LTA | Card. | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `SignedData.certificates` | shall | shall | shall | shall | 1 | (a, b) |
| `content-type`=`id-data`, `message-digest` | shall | shall | shall | shall | 1 | |
| `signer-attributes-v2` | may | may | may | may | 0..1 | |
| `content-time-stamp` | may | may | may | may | ≥0 | |
| `signature-policy-identifier` | may | may | may | may | 0..1 | |
| `commitment-type-indication` | cond. | cond. | cond. | cond. | 0..1 | only without `/Reason` (d) |
| ESS signing-certificate / -v2 | shall (one of) | shall | shall | shall | 0..1 | (e, f) |
| Claimed signing time: `/M` | shall | shall | shall | shall | 1 | (g) |
| `signing-time` CMS attribute | **shall not** | shall not | shall not | shall not | 0 | |
| `/Contents`, `/Filter`, `/ByteRange`, `/SubFilter` | shall | shall | shall | shall | 1 | `/SubFilter` = **`ETSI.CAdES.detached`** (l); the ByteRange covers the whole file except Contents (k); ISO 32000-1 PKCS#1/PKCS#7 handling shall not be used (i) |
| `/Location`, `/Name`, `/ContactInfo` | may | may | may | may | 0..1 | |
| `/Reason` | cond. | cond. | cond. | cond. | 0..1 | not with commitment-type or policy id (m) |
| `/Cert` | shall not | shall not | shall not | shall not | 0 | |
| Trusted time: `signature-time-stamp` **or** document time stamp | * | **shall** | shall | shall | ≥0 each | (n)–(q); space can be reserved for the time stamp (q) |
| Cert + revocation values: **DSS** dictionary | * | * | **shall** | shall | ≥1 | §5.4.2.2, (r)–(u) |
| DSS/VRI | * | * | cond. | cond. | ≥0 | VRI "should not be used" (v) |
| Trusted time for validation data: **document time stamp** (`/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`) | * | * | * | **shall** | ≥1 | §5.4.3, (w)–(y) |

DSS dictionary (§5.4.2.2): `/Type /DSS`, `/VRI` (keys = uppercase hex SHA-1 of the signature's `/Contents` string), `/Certs`, `/OCSPs` (`OCSPResponse`; accept `BasicOCSPResponse` when validating), `/CRLs`. VRI (§5.4.2.3): `/Cert`, `/CRL`, `/OCSP`, `/TU`, `/TS`. DocMDP restrictions do not apply to DSS/VRI or DocTimeStamp updates (§5.4.2.3, §5.4.3). Encryption is applied before signing (§5.5). Extensions dictionary: `/ESIC` BaseVersion 1.7, ExtensionLevel 1 and/or 2, or `/ADBE` ExtensionLevel 8 (§5.6).

Draft V1.3.0 (not published): supports both PDF 1.7 (ISO 32000-1) and PDF 2.0 (ISO 32000-2); with ISO 32000-2, MD5/SHA-1 shall not be used for new signatures; no `/ESIC` or `/ADBE` extensions in PDF 2.0; each revision's conformance is judged by its own PDF version (§4.1, §5.6.2–5.6.3) [EN142-1-draft].

### 2.5 JAdES baseline (TS 119 182-1 V1.2.1, §6.3 Table 1)

General (§4): the signed components go in the JWS Protected Header. The JWS Unprotected Header holds only `etsiU` (a JSON array), which forces JSON serialization. The payload is attached or detached (several detached objects through `sigD`).

| Item | B-B | B-T | B-LT | B-LTA | Card. | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `alg` | shall | shall | shall | shall | 1 | |
| `cty` | cond. | cond. | cond. | cond. | 0..1 | §5.1.3 |
| `kid`, `x5u` | may | may | may | may | 0..1 | |
| `x5c` | cond. | cond. | cond. | cond. | 0..1 | **mandatory under CIR 2026/248** |
| `crit` | cond. | cond. | cond. | cond. | | required, listing `sigD`, when `sigD` is present (§5.1.9) |
| Claimed signing time: `iat` / `sigT` | cond. | cond. | cond. | cond. | 0..1 | **from 2025-07-15 `iat` shall be used and `sigT` shall not be in new signatures** (a; §5.1.11, §5.2.1) |
| Signing-cert reference: `x5t#S256` / `x5t#o` / `sigX5ts` (or `x5c`) | cond. | cond. | cond. | cond. | 1 | at least one (§5.1.7) |
| `sigD` (mechanisms `http://uri.etsi.org/19182/HttpHeaders`, `…/ObjectIdByURI`, `…/ObjectIdByURIHash`) | may | may | may | may | 0..1 | HttpHeaders requires `b64:false` (RFC 7797) (§5.1.10, §5.2.8) |
| `srAts`, `srCms`, `sigPl`, `sigPId` | may | may | may | may | 0..1 | |
| `cSig` (countersignature, in etsiU) | may | may | may | may | ≥0 | §5.3.2 |
| `adoTst` | may | may | may | may | 0..1 | |
| `sigPSt` | cond. | cond. | cond. | cond. | 0..1 | needs `sigPId` with `digVal` (b) |
| `sigTst` | * | **shall** | shall | shall | ≥1 | one TST each (c, d) |
| `xVals`, `rVals`, `axVals`, `arVals`, `anyValData` | * | * | cond. | cond. | | §5.3.5 |
| `xRefs`, `rRefs`, `axRefs`, `arRefs`, `sigRTst`, `rfsTst` | * | * | **shall not** | shall not | B-LT+: 0 | Annex A |
| TST validation data: `tstVD` / embedded in the TST / `anyValData` | * | * | **shall** | shall | | (j, k) |
| `arcTst` | * | * | * | **shall** | ≥1 | §5.3.6.2; message imprint with base64url incorporation vs clear-JSON incorporation (§5.3.6.2.3–4) |

The etsiU elements may each be base64url-encoded or clear JSON; this changes the imprint computation (§5.3.6.2, A.1.5).

### 2.6 ASiC (EN 319 162-1/-2 V1.1.1)

| Container | Contents | Baseline levels | Source |
| --- | --- | --- | --- |
| ASiC-S + CAdES | 1 data file at root + `META-INF/signature.p7s` (detached CAdES, ≥1 SignerInfo) | B-B…B-LTA = the signature level | 162-1 §4.3.3.2(4b), §5.3.2.2 |
| ASiC-S + XAdES | 1 data file + `META-INF/signatures.xml` (`asic:XAdESSignatures`, ≥1 detached `ds:Signature`) | B-B…B-LTA | 162-1 §4.3.3.2(4c), §5.3.2.3 |
| ASiC-S + time stamp | `META-INF/timestamp.tst`; long term through `ASiCArchiveManifest` + TST | not baseline (additional, 162-2 §4.2.1) | 162-1 §4.3.4, 162-2 |
| ASiC-S + ER | `META-INF/evidencerecord.ers` (RFC 4998) / `.xml` (RFC 6283) | not baseline | 162-1 §4.3.3.2(4d, 4e) |
| ASiC-E + XAdES | ≥1 file outside META-INF; `META-INF/*signatures*.xml` (root `asic:XAdESSignatures` should be used; ODF/OCF roots allowed); `META-INF/manifest.xml` required in baseline | B-B…B-LTA | 162-1 §4.4.3, §5.3.3 |
| ASiC-E + CAdES | `META-INF/*signature*.p7s` + `META-INF/ASiCManifest*.xml` | additional container (162-2 §4.3.1); in CIR 2026/248 Annex I | 162-1 §4.4.4, 162-2 §4.3.1 |
| ASiC-E + time assertions | `*timestamp*.tst` + ASiCManifest; `ASiCArchiveManifest` | additional (162-2 §4.3.2) | |

Container rules: ZIP per **ISO/IEC 21320-1** (no encryption, stored or deflate only) (§5.3.1). Optional `mimetype` file: first entry, stored, no extra field, so the content starts at offset 38 (A.1). Media types `application/vnd.etsi.asic-s+zip` (`.asics`/`.scs`) and `application/vnd.etsi.asic-e+zip` (`.asice`/`.sce`) (A.2). Schema namespace `http://uri.etsi.org/02918/v1.2.1#` (A.3). Container level = the lowest level among its signatures (§5.1).

### 2.7 Extended (part 2) profiles worth knowing

| Profile | Definition | Source |
| --- | --- | --- |
| CAdES-E-BES / E-EPES / E-T / E-A (on E-T) | More optional than baseline: `signing-time` may be present; E-EPES adds one `signature-policy-identifier`; E-T adds ≥1 `signature-time-stamp`; E-A adds `archive-time-stamp-v3` | EN 319 122-2 §4.3 Table 1 |
| CAdES-E-C / E-X (Type 1: CAdES-C-timestamp; Type 2: time-stamped-certs-crls-references) / E-X-Long / E-X-L (T1/T2) / E-A on them | Reference-based levels | EN 319 122-2 Annex A |
| XAdES-E-BES / E-EPES / E-T / E-A, E-C / E-X / E-X-Long / E-X-L, E-A on them | Same scheme in XAdES | EN 319 132-2 §4.3, Annex A |
| PAdES "CMS signatures in PDF" profile | ISO 32000-2 §12.8; SubFilter `adbe.pkcs7.detached` **or** `ETSI.CAdES.detached` only; one signer; no PKCS#1; SHA-1 phased out; signing-cert attribute may be ignored when validating | EN 319 142-2 §4 |
| PAdES-E-BES | `signing-time` **may** be used (then `/M` not used for time); `ETSI.CAdES.detached` | EN 319 142-2 §5.3 Table 1 |
| PAdES-E-EPES | + `signature-policy-identifier` (1), `/Reason` shall not be present | EN 319 142-2 §5.4 Table 2 |
| PAdES-E-LTV | DSS + document time stamps; validation data by value only | EN 319 142-2 §5.5 |
| XAdES in PDF: XML embedded in PDF (basic and long-term) and XFA forms (basic and LTV) | | EN 319 142-2 §6 |
| PAdES-DTS (document time stamp as "signature") | Not an AdES (no signer identity) | TS 119 142-3 |
| ERS in CAdES / XAdES | Evidence records as unsigned attributes / properties | TS 119 122-3, TS 119 132-3 |

### 2.8 Legacy forms still met in the wild

| Legacy spec (latest) | Forms | Source |
| --- | --- | --- |
| TS 101 733 V2.2.1 (2013) | CAdES-BES, -EPES, -T, -C, -X (T1/T2), -X-L, -A (archive-time-stamp v2/v3) | [TS101733] |
| TS 101 903 V1.4.2 (2010) | XAdES-BES, -EPES, -T, -C, -X, -X-L, -A; namespaces 1.1.1, 1.2.2, 1.3.2, 1.4.1 (AutoFirma still handles 1.1.1–1.4.1, `XAdESConstants.java`) | [TS101903], [AF-src] |
| TS 102 778-1…6 (2009–2010) | PAdES Basic (part 2: `adbe.pkcs7.detached` / `adbe.pkcs7.sha1`), BES/EPES (part 3), LTV (part 4), XAdES in PDF (part 5), visual representation (part 6) | [TS102778] |
| TS 103 171 v2.1.1 / 103 172 v2.2.2 / 103 173 v2.2.1 / 103 174 v2.2.1 | "Baseline profile" v2 (B-Level, T-Level, LT-Level, LTA-Level); **legally required until 2028-02-23** (CIR 2026/248 Annex II) | [CIR-2026-248] |
| TS 102 918 V1.3.1 (2013) | ASiC predecessor | [TS102918] |
| ISO 32000-1 PKCS#1 signatures (`adbe.x509.rsa_sha1`) | PKCS#1 in `/Contents`, certs in `/Cert` (the SubFilter name comes from ISO 32000-1 §12.8.3.2, not read here: UNVERIFIED) | EN 319 142-1 Table 1 req. (i) |

## 3. Packaging and structure variants

| Format | Variant | Source |
| --- | --- | --- |
| CAdES | Attached (eContent present) / detached (eContent absent; data kept apart, byte-exact) | EN 319 122-1 §4.5 |
| CAdES | Signing a precomputed digest (detached; the digest must match `message-digest`) | follows from §4.5 + §5.1.2 (no explicit clause) |
| XAdES | Enveloped (`enveloped-signature` transform or XPath Filter 2), enveloping (`ds:Object`), detached (external URI), internally detached (signature and data are siblings under a parent element) | [XMLDSig11] §1; internally detached as a term: DSS doc §4.1.4 [DSS-doc] |
| XAdES | Signed `ds:Manifest` (indirect references) | EN 319 132-1 §6.3 note 8, req. (bb) |
| XAdES | Signing a single node by Id/XPath; the root element of the enveloping signature | AutoFirma `nodeToSign`, `RootXmlNodeName` [AF-xades-params] |
| JAdES | Compact serialization (no etsiU, so B-B only in practice), flattened JSON, general JSON (several signatures = parallel) | TS 119 182-1 §4; RFC 7515 §3, §7 |
| JAdES | Attached / detached payload; `sigD` (HttpHeaders, ObjectIdByURI, ObjectIdByURIHash); `b64:false` unencoded payload | TS 119 182-1 §4, §5.1.10, §5.2.8; RFC 7797 |
| PAdES | Invisible (zero-size widget) vs visible (widget with an appearance stream) signature field | ISO 32000-1 §12.7.4.5 / §12.5.6.19: UNVERIFIED (ISO text not read) |
| PAdES | Certification (author) signature with DocMDP `/P` 1, 2 or 3 vs approval signature; FieldMDP locks | EN 319 142-1 §5.4.2.3 note (ISO 32000-1 §12.8.2.2) |
| PAdES | Incremental update per signature; ByteRange = the whole revision | EN 319 142-1 Table 1 (k); draft V1.3.0 §4.1(a) |
| ASiC | -S (one data object; it may itself be a ZIP) / -E (many objects, many signatures, additions later) | EN 319 162-1 §4.3–4.4 |

## 4. Operations beyond one signature

| Operation | Per format | Source |
| --- | --- | --- |
| Parallel signatures (co-sign) | CAdES: several SignerInfo in one SignedData. XAdES: sibling `ds:Signature` elements (ASiC `XAdESSignatures`). JAdES: general JSON serialization. PAdES: **one SignerInfo per PDF signature**, so a parallel signature is a new signature field in a new incremental update. ASiC: several signatures in -S `signature.p7s`/`signatures.xml` or -E files | EN 319 122-1 §4.4, §4.6; EN 319 142-1 §4.1(a); EN 319 162-1 §4.3.3.2; RFC 7515 §7.2 |
| Counter-signatures | CAdES `countersignature` (unsigned attribute, recursive). XAdES `CounterSignature` (enveloped) or detached countersignature (`ds:Reference/@Type`). JAdES `cSig` in etsiU | EN 319 122-1 §5.2.7; EN 319 132-1 §5.2.7.1–2; TS 119 182-1 §5.3.2 |
| Serial PDF signatures | Each in its own incremental update; DocMDP permissions decide what is allowed after a certification signature | EN 319 142-2 A.4; EN 319 142-1 §5.4.2.3 note |
| Augmentation B-B→B-T | Add `signature-time-stamp` / `SignatureTimeStamp` / `sigTst` / PAdES signature TST or DocTimeStamp. The TST must be issued before signing-cert revocation or expiry | EN 319 102-1 §4.3.3; 122-1 (m); 132-1 (o); 182-1 (d) |
| Augmentation →B-LT | Add certificates and revocation data for the signer, CA chain, TSA and countersignatures (CAdES `SignedData.certificates/crls`; XAdES `CertificateValues`/`RevocationValues`/`TimeStampValidationData`; JAdES `xVals`/`rVals`/`tstVD`; PAdES DSS) | EN 319 102-1 §4.3.4 |
| Augmentation →B-LTA | CAdES `archive-time-stamp-v3` + `ats-hash-index-v3`; XAdES `ArchiveTimeStamp` 1.4.1; JAdES `arcTst`; PAdES DSS + DocTimeStamp; ASiC-S TST + `ASiCArchiveManifest` | EN 319 102-1 §4.3.5 |
| Archive time stamp renewal | Add the validation data of the previous archive TST, then a new archive TST (repeatable). PAdES: DSS update + new DocTimeStamp; keep previous DSS values | 122-1 (s); 132-1 (aa); 182-1 (m); 142-1 §5.4.1, (x); 162-1 §4.3.4 |
| Interop test augmentation cases | `CAdES/Aug/1..4`, `XAdES/AUG/1..4`, `PAdES/Aug/1..4` | TS 119 124-2 §9, TS 119 134-2, TS 119 144-2 |

## 5. Shared building blocks

| Block | Spec(s) | Notes |
| --- | --- | --- |
| CMS SignedData | RFC 5652 | DER for signed attributes; BER tolerated (EN 319 122-1 §4.7) |
| ESS signing-certificate / -v2 | RFC 2634, RFC 5035 | `ESSCertIDv2`; `issuerSerial` should be omitted |
| CMS algorithm protection | RFC 6211 | ECDSA / PSS substitution protection (122-1 note 8) |
| OCSP in CMS `RevocationInfoChoice` | RFC 5940 | `SignedData.crls.other` |
| Time stamps | RFC 3161, RFC 5816 (ESSCertIDv2), **EN 319 422 V1.1.1 (2016-03)** | Client: support `reqPolicy`, `nonce`, `certReq`; must handle `accuracy`; nonce echo. Server: `policy`, `accuracy` ≥1 s, `ordering` false, no critical extensions, SigningCertificate(V2) in the TST. HTTP(S) transport. Qualified TST: `qcStatements` with `esi4-qtstStatement-1` (OID `0.4.0.19422.1.1`) (EN 319 422 §4–9, Annex B) |
| OCSP | RFC 6960 | DSS `/OCSPs` stores `OCSPResponse`; accept `BasicOCSPResponse` |
| CRL, path validation | RFC 5280 §6 | EN 319 102-1 §5.2.6 builds on it |
| Path building, AIA fetching | RFC 4158 (informative), RFC 5280 §4.2.2.1 | Certs "available to verifiers" via AIA (122-1 note 2) |
| Signature policies | TS 119 172-1 V1.1.1 (2015-07) (human-readable doc + commitment types Annex B); TS 119 172-2 V1.1.1 (2019-12) XML; TS 119 172-3 V1.1.1 (2019-12) ASN.1; legacy TR 102 038 (XML, 2002) and TR 102 272 (ASN.1, 2003) | CAdES `signature-policy-identifier` + `SigPolicyQualifierInfo` (`spuri`, `spUserNotice`, `spDocSpecification`); XAdES `SignaturePolicyIdentifier` (+ `SPURI`, `SPUserNotice`, `SPDocSpecification`); JAdES `sigPId`; implied policy; policy stores. The hash covers the policy document (with optional transforms in XAdES) |
| Commitment types | TS 119 172-1 Annex B: proofOfOrigin…proofOfCreation, OIDs `1.2.840.113549.1.9.16.6.1–6`, URIs `http://uri.etsi.org/01903/v1.2.2#ProofOf…` | The TS text lists "Proof of sender" with the `proofOfDelivery` OID (…6.3), an apparent erratum |
| Signer location / role | CAdES `signer-location`, `signer-attributes-v2` (claimed, `certifiedAttributesV2`, `signedAssertions`); XAdES `SignatureProductionPlaceV2`, `SignerRoleV2`; JAdES `sigPl`, `srAts` | EN 319 122-1 §5.2.5–6; EN 319 132-1 §5.2.5–6; TS 119 182-1 §5.2.4–5 |
| Content description | CAdES `content-hints` (RFC 2634), `mime-type`; XAdES `DataObjectFormat`; JAdES `cty` | EN 319 122-1 §5.2.4; 132-1 §5.2.4 |
| MIME / S/MIME | RFC 2045, RFC 8551 | EN 319 122-1 Annex E (informative) |
| XML DSig | [XMLDSig11] (W3C Rec 2013) | |
| Canonicalization | C14N 1.0 (2001), C14N 1.1 (2008), Exclusive C14N 1.0 (2002), each with/without comments | EN 319 132-1 req. (d) |
| Transforms | base64, XPath 1.0, enveloped-signature, XSLT, XPath Filter 2.0, OOXML RelationshipTransform (ECMA-376 / ISO/IEC 29500 §12.2.4.26) | EN 319 132-1 req. (g) |
| XML security URIs | RFC 6931, RFC 9231 | algorithm identifiers (TS 119 312 §10.3) |
| PDF | ISO 32000-1 §12.8 (signature dictionary, ByteRange, `/Contents` hex, DocMDP §12.8.2.2), ISO 32000-2 §12.8, **ISO/TS 32001** (SHA-3/SHAKE256 in PDF), **ISO/TS 32002** (ECDSA P-curves, Brainpool, EdDSA in PDF) | PAdES DSS/VRI/DocTimeStamp (EN 319 142-1 §5.4); SubFilters `adbe.pkcs7.detached`, `ETSI.CAdES.detached`, `ETSI.RFC3161`, legacy `adbe.pkcs7.sha1`, `adbe.x509.rsa_sha1` (ISO 32000-2 deprecates the SHA-1 ones: draft 142-1 note 2). Free ISO 32000 bundle: [PDFA-32002], [PDFA-32001] |
| PDF/A | ISO 19005-1, ISO 19005-4 | EN 319 142-2 A.6–A.7 |
| JOSE | RFC 7515 (JWS), RFC 7797 (b64), RFC 7518 (JWA), RFC 7519 (JWT, for `iat`), RFC 8037 (EdDSA in JOSE) | TS 119 182-1 §5.1 |
| ZIP | ISO/IEC 21320-1 (Document Container File), PKWARE APPNOTE | EN 319 162-1 §5.3.1 |
| Evidence records | RFC 4998 (ERS), RFC 6283 (XMLERS) | TS 119 122-3, TS 119 132-3, EN 319 162-1 |
| AdES URIs | TS 119 192 V1.2.1 (2023-02) root `http://uri.etsi.org/ades` | |
| Trust anchors via trusted lists | TS 119 612 V2.4.1; the TL itself is an enveloped XAdES signature (TS 119 612 Annex B) | §7 |

## 6. Algorithms (TS 119 312 V2.1.1, 2026-06)

The security assessment is delegated to **ECCG Agreed Cryptographic Mechanisms v2.0 (April 2025)** (§4, ref [14]). R = recommended, L = legacy. The claim that ECCG ACM succeeds SOG-IS ACM is UNVERIFIED (SOG-IS was not consulted).

| Hash (§5.1 Table 1) | Status |
| --- | --- |
| SHA-256, SHA-384, SHA-512, SHA3-256/384/512 | R |
| SHA-224 | L[2028] in Table 1, **but** Annex D Table D.1 lists it as discontinued in V2.1.1 (constraint < 2026-01-01): an internal inconsistency |
| SHA-512/256 | use SHA3-256 or SHA-512 instead (§5.2.1) |
| SHA-1, RIPEMD-160, Whirlpool, MD5 | discontinued (Annex D Table D.1: SHA-1 constraint < 2012-08-01); validation only, for legacy |

| Signature (§6.2 Table 2) | Status | Key notes |
| --- | --- | --- |
| RSA-PSS | R | §6.2.2.1 |
| RSA PKCS#1 v1.5 | **L** | "may be used" |
| RSA key size | 1900–2999 bits: L[2026], **no new certificates after 2026-12-31**, those certificates valid until 2028-12-31 at most; ≥3000: R | §8.4 Table 6 |
| ECDSA | R | curves FRP256v1, brainpoolP256r1/384r1/512r1, P-256, P-384, P-521 (Table 3) |
| EdDSA (Ed25519, Ed448) | R by ETSI (not an ECCG-agreed scheme) | §6.2.2.4 |
| DSA | R (≥3000/250 bits; <3000 L[2026]) | Table 7 |
| EC-SDSA-opt | L | |
| ML-DSA-44/65/87 (pure only, not HashML-DSA) | R | §6.2.2.5 |
| SLH-DSA (192/256, SHA-2 and SHAKE); pure only in CMS-based AdES | R | §6.2.2.6 |
| LMS, XMSS | R (conditional: stateful) | §6.2.2.7 |
| Hybrid (classical + PQ) | for long-term needs beyond 2030 | §6.4 |

Per-format matrix (Annex A.2 CAdES/PAdES, A.3 XAdES, Table A.1/A.2): **issuers** shall support SHA-256 and should support RSA-PSS, DSA, EdDSA or ECDSA, plus ML-DSA or SLH-DSA; **verifiers** shall support SHA-256/384/512 and RSA-PKCS1v1_5, RSA-PSS, DSA, EdDSA, ECDSA, **and ML-DSA, SLH-DSA**. TST (A.9 Table A.8): requesters shall support SHA-256 and TST signatures RSA, DSA, EdDSA, ECDSA; verifiers also SLH-DSA (and XMSS/LMS, per the table). Annex D gives default "cryptographic constraint" dates for validating discontinued algorithms (e.g. RSA-1024 < 2019-10-01, ECDSA-224 < 2021-10-01). §10: OIDs and URIs.

## 7. Validation

| Piece | Spec | Content |
| --- | --- | --- |
| Validation model and processes | **EN 319 102-1 V1.4.1 (2024-06)** | Basic building blocks §5.2: format checking, signing-cert identification, validation context initialization, revocation freshness checker, X.509 certificate validation, cryptographic verification, signature acceptance validation (SAV), presentation. Processes: **basic signatures §5.3**, time-stamp validation §5.4, **signatures with time and with LT material §5.5**, **long-term availability (LTA) §5.6** (past certificate validation, validation time sliding, POE extraction, past signature validation). Constraints: X.509, cryptographic, signature elements (§5.1.4). Annex C: applicability and format conformance. Creation side: §4 (classes, DTBS, DTBSR) |
| Main indications | EN 319 102-1 §5.1.3 Table 5 | **TOTAL-PASSED**, **TOTAL-FAILED**, **INDETERMINATE** (component processes return PASSED / FAILED / INDETERMINATE) |
| Sub-indications, TOTAL-FAILED | Table 6 | FORMAT_FAILURE, HASH_FAILURE, SIG_CRYPTO_FAILURE, REVOKED, EXPIRED, NOT_YET_VALID |
| Sub-indications, INDETERMINATE | Table 6 | SIG_CONSTRAINTS_FAILURE, CHAIN_CONSTRAINTS_FAILURE, CERTIFICATE_CHAIN_GENERAL_FAILURE, CRYPTO_CONSTRAINTS_FAILURE, EXPIRED, NOT_YET_VALID, FORMAT_FAILURE, POLICY_PROCESSING_ERROR, SIGNATURE_POLICY_NOT_AVAILABLE, TIMESTAMP_ORDER_FAILURE, NO_SIGNING_CERTIFICATE_FOUND, NO_CERTIFICATE_CHAIN_FOUND, NO_CERTIFICATE_CHAIN_FOUND_NO_POE, REVOKED_NO_POE, REVOKED_CA_NO_POE, OUT_OF_BOUNDS_NOT_REVOKED, OUT_OF_BOUNDS_NO_POE, REVOCATION_OUT_OF_BOUNDS_NO_POE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, NO_POE, TRY_LATER, SIGNED_DATA_NOT_FOUND. The list is taken from the V1.4.1 text, whose table extracts poorly; it matches DSS's `SubIndication` enum, which adds ATTESTATION_CONSTRAINTS_FAILURE [DSS-enum] |
| Validation report | **TS 119 102-2 V1.4.1 (2023-06)** | XML, namespace `http://uri.etsi.org/19102/v1.4.1#`: ValidationReport, SignatureValidationReport, SignatureIdentifier, status indication / sub-indication, validation constraints evaluation report, validation objects, signer information. **Legally referenced by CIR 2025/1945** |
| Signature validation policy / constraints | TS 119 172-1 Annex A.4 (constraint tables; e.g. `RevocationCheckingConstraints`, `RevocationFreshnessConstraints`, `SetOfTrustAnchors`, `CryptographicConstraints`) | used by CIR 2025/1945 |
| EU QES applicability rules | **TS 119 172-4 V1.2.1 (2026-02)** (CIR 2025/1945 cites V1.1.1) | two rule sets: `id-etsi-sarc-realTimeReq`, `id-etsi-sarc-realTimeNotReq`; requires the LTA validation process; trust anchors from TS 119 615 §4.3 with service type `http://uri.etsi.org/TrstSvc/Svctype/CA/QC` |
| Trusted lists | **TS 119 612 V2.4.1 (2025-08)** (CIR 2025/1945 cites V2.3.1) | TL XML format, scheme info, TSP and service info, service history, XAdES signature; EU LOTL at `https://ec.europa.eu/tools/lotl/eu-lotl.xml` [DSS-doc] |
| Qualified status determination | **TS 119 615 V1.4.1 (2026-05)** | §4.1 authenticate the LOTL; §4.2 authenticate a TL; §4.3 services matching a cert; §4.4 EU qualified certificate determination; §4.5 QSCD determination; §4.7 qualified TST; §4.8–4.13 other qualified services |
| QCStatements | **EN 319 412-5 V2.6.1 (2026-05)** | QcCompliance, QcSSCD (QSCD), QcType (esign / eseal / web), QcLimitValue, QcRetentionPeriod, QcPDS, QcCClegislation, **QcQSCDlegislation**, **QcIdentMethod** (eIDAS / eIDAS2 Art. 24 identification-method values `eIDAS1-ab`, `eIDAS1-cd`, `eIDAS2-acd`, `eIDAS2-b`) |
| Validation application requirements | TS 119 101 V1.1.1 (2016-03) | legally referenced by CIR 2025/1945 (REQ-4.3-02) |
| Validation services (context) | TS 119 441 V1.3.1 (2025-10) policy; TS 119 442 V1.1.1 (2019-02) protocol (validate / augment, XML and JSON bindings, on OASIS DSS-X 2.0) | |

## 8. Conformance testing

ETSI publishes **no** conformance or interoperability test specification for JAdES (there is no `119184` folder in `etsi_ts/119100_119199`), and the CAdES/XAdES/PAdES/ASiC ones date from 2016. They target the 2016 V1.1.1 ENs, not EN 319 122-1 V1.3.1, EN 319 132-1 V1.3.1, EN 319 142-1 V1.2.1 or PDF 2.0.

| Doc | Version | Content | Test IDs found (count per prefix) |
| --- | --- | --- | --- |
| TR 119 124-1 | V1.1.1 (2016-06) | CAdES testing overview | |
| TS 119 124-2 | V1.1.1 (2016-06) | interop, CAdES baseline: B-B §5, B-T §6, B-LT §7, B-LTA §8, augmentation §9, negative §10 | `CAdES/BB/1..9`, `BBN/1..11`, `BT/1..3`, `BTN/1..7`, `BLT/1..4`, `BLTA/1..7`, `BLTAN/1..2`, `Aug/1..4` |
| TS 119 124-3 | V1.1.1 (2016-06) | interop, extended CAdES | `BES/1..7`, `BESN/1..6`, `EPES/1..3`, `EPESN/1..2`, `T/1..2`, `TN/1..6`, `C/1..4`, `X/1..4`, `XL/1..4`, `A/1..11`, `AN/1..4`, `Aug/1..11` |
| TS 119 124-4 | V1.1.1 (2016-06) | conformance assertions, CAdES baseline (per attribute and field: content-type, message-digest, CMSversion, DigestAlgorithmIdentifiers, eContent, certificates, crls, SignerInfos, signing-time, ESS, countersignature, content-reference/-identifier/-hints, commitment, signer-location, signer-attributes-v2, content-time-stamp, mime-type, policy…) | |
| TS 119 124-5 | V1.1.1 (2016-06) | conformance assertions, extended CAdES | |
| TR 119 134-1 / TS 119 134-2 / -3 / -4 | V1.1.1 (2016-06) | XAdES; same structure | -2: `XAdES/BB/1..17`, `BBN/1..8`, `NB/1..4`, `BT/1..4`, `BTN/1..9`, `BLT/1..8`, `BLTA/1..10`, `BLTAN/1..3`, `AUG/1..4`; -3: `EBES`, `EBESN`, `EEPES`, `EEPESN`, `ET`, `ETN`, `EC`, `EX`, `EXLong`, `EXL`, `EA`, `AUGC/X/XL/A` |
| TS 119 134-5 | **V2.1.1** (2016-06) | conformance, extended XAdES | |
| TR 119 144-1, TS 119 144-3 / -4 / -5 | V1.1.1 (2016-06) | PAdES | -3: `PAdES/CMS`, `CMSN`, `BES`, `BESN`, `EPES`, `LTV`, `LTVN`, `XML`, `XFA` |
| TS 119 144-2 | **V2.1.1** (2016-06) | interop, PAdES baseline | `PAdES/BB/1..7`, `BBN/1..6`, `BT/1..4`, `BTN/1..7`, `BLT/1..4`, `BLTA/1..4`, `BLTAN/1..2`, `Aug/1..4` |
| TR 119 164-1, TS 119 164-3 / -4 / -5 | V1.1.1 (2016-06) | ASiC | -3: `ASiC-S/CS`, `ASiC-S/TL`, `ASiC-E/CS`, `ASiC-E/ACAdES`, `ASiC-E/ATA`, `ASiC-E/XAdES-CSC` |
| TS 119 164-2 | **V2.1.1** (2016-06) | interop, ASiC baseline | `ASiC-S/{C,X}{BB,BBN,BT,BTN,BLT,BLTA}`, `ASiC-E/{X,C}…`, `ASiC-S/BCS/1..5`, `ASiC-E/BCS/1..5` |

The IDs were taken mechanically from the PDF text (so the counts are a lower bound); parts 4 and 5 are organised by clause and attribute rather than numbered cases.

| Resource | Status | Source |
| --- | --- | --- |
| ETSI Signatures Conformance Checker (online, free, from CTI) | covers XAdES, CAdES, PAdES and ASiC baseline (the EC page); the portal index reportedly adds JAdES (UNVERIFIED: the portal needs JavaScript); checks structure and the signature value, **not** certificate chains or validity; registration reportedly required (UNVERIFIED) | [ETSI-SCC], [EC-SCC] |
| ETSI Plugtests | Remote events run by ETSI CTI, with registration on each event page: JAdES 2021, LTA augmentation and validation 2023, **CB-AdES Plugtests 2026-10-26 → 2026-11-23** (seen on the ETSI events listing; details UNVERIFIED) | [ETSI-JAdES-PT], [ETSI-LTA-PT], [ETSI-CTI-ESI] |

## 9. Remote signing

| Spec | Version | Relevance |
| --- | --- | --- |
| TS 119 432 | **V1.3.1 (2026-03)** | Protocols for remote AdES / signature-value creation (server signing only); maps onto **CSC API 2.2.0.0** and OASIS DSS-X; no mandatory binding (§1, ref [1]) |
| CSC API | **v2.2.0.0 (2025-11-04)**, data model 1.0.0 (2025-10-16) | REST plus OAuth 2.0 and OpenID4VC; `signatures/signHash` fits the two-phase design [CSC] |
| TS 119 431-1 | V1.3.1 (2024-12) | TSP policy for operating a remote QSCD/SCDev (SSAS), updated for eIDAS 2 |
| TS 119 431-2 | V1.2.1 (2023-06) | TSP policy for a signature creation application service component (SCASC) |

## 10. Spanish specifics

### 10.1 Política de Firma Electrónica y de Certificados de la AGE

| Field | Value | Source |
| --- | --- | --- |
| Current version | **1.9**, issued 2012-11-19 (approved by the CSAE Comisión Permanente 2012-05-30); no newer version found (absence UNVERIFIED) | [AGE-pol] §3.1 |
| OID | `2.16.724.1.3.1.1.2.1.9` (`urn:oid:` form accepted); v1.8 = `…2.1.8` | [AGE-pol] §2.2, §3.1; [AF-policy] |
| Document URL (policy qualifier) | `https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf` | [AF-policy] |
| Hash | SHA-1 `G7roucf600+f03r/o0bAOQ6WAs0=` (the same for XAdES, CAdES and PAdES in AutoFirma), **checked by downloading the PDF on 2026-10-21**; SHA-256 of the same file `Dkx2R3nMv8kWo7iSAh+/1SQ70hfseOEaQbpJnURk+pg=`. v1.8: XAdES `V8lVVNGDCPen6VELRD1Ja8HARFk=`, CAdES/PAdES `7SxX3erFuH31TvAw9LZ70N7p1vA=` (AutoFirma only, not rechecked) | [AF-policy] |
| Formats admitted | XAdES TS 101 903 v1.2.2/1.3.2 (1.4.1 from 2013-12-31); CAdES TS 101 733 v1.6.3/1.7 ("1.8.1" from 2013-12-31); PAdES TS 102 778-3 v1.2.1 (+ part 4 for LTV) | [AGE-pol] §2.6 |
| Level | Generate at least the **EPES class** of one format; verify the basic class of all formats | [AGE-pol] §2.6 |
| Policy document formats | XML per TR 102 038 or ASN.1 per TR 102 272 recommended | [AGE-pol] §2.2 |
| Structure annex | XAdES-EPES §4.1, CAdES-EPES §4.2 | [AGE-pol] Annex 1 |
| Legal frame | NTI Política de Firma: BOE-A-2011-13171 (2011); later revision UNVERIFIED; RD 203/2021 (state policy approved by resolution) | [BOE-NTI-2011], [BOE-RD-203-2021] |

The admitted-formats list predates the EN 319 1x2 baselines; how the AGE reconciles it with CIR 2026/248 is UNVERIFIED.

### 10.2 FacturaE signature policy

| Field | Value | Source |
| --- | --- | --- |
| Policy v3.1 identifier | `http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf` | [FE-pol]; [AF-facturae] |
| Hash v3.1 | SHA-1 `Ohixl6upD6av8N7pEvDABhEL6hM=` (AutoFirma) | [AF-facturae] |
| **Surprise** | The PDF served today (redirect to `facturae.gob.es/.../Politica_Firma_formato_facturae_v3_1.pdf`) hashes to SHA-1 `f/LPQFpMc/ha+1dJ+Y5y11OPVnM=`, not the value above, and the example inside it shows `xmfh8D/Ec/hHeE1IB4zPd61zHIY=` (the v3.0 hash). The policy hash must be a constant, not computed from a download | computed 2026-10-21 |
| Policy v3.0 | identifier `http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf` (with spaces), SHA-1 `xmfh8D/Ec/hHeE1IB4zPd61zHIY=` | [AF-facturae] |
| Profile | XAdES-EPES (TS 101 903 v1.2.2) **enveloped**. References: whole document (`URI=""` + enveloped transform), `#SignedProperties`, `#KeyInfo` (signed). `KeyInfo` carries the cert. `SignerRole/ClaimedRoles` ∈ {`supplier`/`emisor`, `customer`/`receptor`, `third party`/`tercero`}. Long-term form: XAdES-X-L (CompleteCertificateRefs, CertificateValues, CompleteRevocationRefs, RevocationValues), with a TST "close to" SigningTime | [FE-pol] §1.2–1.3, §2 |
| AutoFirma enforcement | Only policies 3.0/3.1 accepted; no cosign; rejects already-signed invoices; restricted extraParams | [AF-facturae] |

### 10.3 AutoFirma capabilities (source at commit `bd9254be`, 2026-10-19)

| Aspect | Values | Source |
| --- | --- | --- |
| Format identifiers | `CAdES`, `CAdEStri`, `CAdES-ASiC-S`(+`-tri`), `XAdES`, `XAdEStri`, `XAdES-ASiC-S`(+`-tri`), `XAdES Detached`/`Enveloped`/`Enveloping`/`Externally Detached`, `XMLDSig` (same four variants), `PAdES`, `PAdEStri`, `Adobe PDF`(+TriPhase), `FacturaE`(+`tri`, alias `Factura-e`), `CMS/PKCS#7`, `NONE`/`PKCS1`/`PKCS#1`(+`NONEtri`), `OOXML`, `ODF`, `SOAP`, `auto` | [AF-const] |
| Operations | `sign`, `cosign` (two overloads), `countersign` with targets `tree`, `leafs`, `nodes`, `signers`; batch signing (`afirma-crypto-batch-client`, `afirma-server-triphase-signer`); CLI `sign`, `cosign`, `countersign`, `verify`, `batchsign`, `listaliases`; protocol: sign, sign-and-save, batch, select cert, save, load (`UrlParameters*` classes) | [AF-cst], [AF-cli], [AF-proto] |
| Profiles and modes | `profile` = `baseline` / `advanced`; `mode` = `implicit` (attached) / `explicit` (detached) | [AF-const] |
| Algorithms | `SHA1/256/384/512withRSA`, `SHA1withDSA`, `SHA1/224/256/384/512withECDSA`, `NONEwithRSA/ECDSA` (no PSS, no EdDSA) | [AF-const] |
| PDF SubFilters recognised | `adbe.pkcs7.detached` (default, "for Adobe Reader"), `ETSI.CAdES.detached`, `adbe.pkcs7.sha1`, `ETSI.RFC3161` (document TST); `tsType` 1 = signature TST, 2 = document TST, 3 = both | [AF-pdfutil], [AF-pdf-params] |
| CAdES extraParams | `mode`, `profile`, `precalculatedHashAlgorithm`, `signingCertificateV2`, `includeOnlySignningCertificate`, `includeSigningTimeAttribute`, `includeContentHintAttribute`, `contentTypeOid`, `contentDescription`, `includeMimeTypeAttribute`, `mimeType`, policy (`policyIdentifier`, `policyIdentifierHash`, `policyIdentifierHashAlgorithm`, `policyQualifier`, `doNotIncludePolicyOnSigningCertificate`), `signerClaimedRoles`, `signatureProduction*`, `commitmentTypeIndications` (+ qualifiers), TSA (`tsaURL`, `tsaPolicy`, `tsaHashAlgorithm`, `tsaRequireCert`, `tsaUsr`/`tsaPwd`, `tsaSslPkcs12File`…), `allowSignLTSignature` | [AF-cades-params] |
| XAdES extraParams | `format`, `mode`, `profile`, `uri`, `nodeToSign`, `insertEnvelopedSignatureOnNodeByXPath`, `useManifest`, `referencesDigestMethod`, `canonicalizationAlgorithm`, `xadesNamespace`, `signedPropertiesTypeUrl`, `xmlSignaturePrefix`, KeyInfo options (`keepKeyInfoUnsigned`, `addKeyInfoKeyValue`/`KeyName`/`X509IssuerSerial`), `mimeType`/`encoding`/`contentTypeOid`, policy (+`policyDescription`), `signerClaimedRoles`, `signatureProduction*` (incl. street address), commitment types (ProofOfDelivery…), `facturaeSign`, `RootXmlNodeName`/`Namespace`/`Prefix`, `avoidAGEPolicyIncompatibilities`, `allowSignLTSignature`, `validatePkcs1` | [AF-xades-params] |
| PAdES extraParams | visible signature (`signaturePage(s)`, `signaturePositionOnPage*`, `signatureRubricImage`, `layer2Text`/font/colour, `layer4Text`, `signatureRotation`, `obfuscateCertText`), `signatureField`, `certificationLevel` 0–3, `signatureSubFilter`, `signReason`, `signatureProductionCity`, `signerContact`, `signTime`, policy, commitment types, `signingCertificateV2`, `alwaysCreateRevision`, `pdfVersion`, `compressPdf`, attachments (`attach*`), image stamp (`image*`), passwords (`ownerPassword`, `userPassword`), TSA (`tsType`, `tsaURL`, extensions, SSL key and trust stores), `signReservedSize`, safety checks (`allowShadowAttack`, `pagesToCheckShadowAttack`, `allowModifiedForm`, `allowSigningCertifiedPdfs`, `allowCosigningUnregisteredSignatures`, `checkCertificates`) | [AF-pdf-params] |
| ASiC-S | `asicsFilename` | [AF-src] |
| Policy shortcuts | `expPolicy=FirmaAGE` / `FirmaAGE19` / `FirmaAGE18` | [AF-policy] |
| Upgrade to long-term | through an external platform (`SignEnhancer` interface); no native B-LT/B-LTA generation found (UNVERIFIED that none exists) | [AF-src] |

## 11. DSS as validation oracle

| Item | Value | Source |
| --- | --- | --- |
| Latest release | **DSS 6.5.1 (2026-10-14)**; docs v6.5 (2026-08-28) | [DSS-rel], [DSS-doc] |
| Signature levels (`SignatureLevel` enum) | XAdES/CAdES: `BES`, `EPES`, `T`, `LT`, `C`, `X`, `XL`, `A`, `ERS`, `BASELINE_B/T/LT/LTA`; PAdES: `BES`, `EPES`, `LTV`, `BASELINE_B/T/LT/LTA`; JAdES: `JAdES`, `BASELINE_B/T/LT/LTA`; CB-AdES: same set; plus `*_NOT_ETSI` (XML, CMS, PDF, JSON, CBOR) | [DSS-enum] |
| Forms | XAdES, CAdES, JAdES, CBAdES, PAdES, PKCS7 | [DSS-enum] |
| Packaging | ENVELOPED, ENVELOPING, DETACHED, INTERNALLY_DETACHED; JWS COMPACT, JSON, FLATTENED_JSON serialization; ASiC-S/-E; counter signatures (§4.8); format × packaging matrix in Table 5 (§4.1.4.1) | [DSS-doc], [DSS-enum] |
| Validation output | ETSI TS 119 102-2 validation report, simple and detailed reports; validation policy (constraint file) | [DSS-doc] |
| Run locally | **No official container image found** (UNVERIFIED); `dss-demonstrations` ships a `Dockerfile` (Maven build → Tomcat 11, JDK 25, port 8080) and a ready-made `dss-demo-bundle` zip/tar.gz from the EC Maven repository (Windows `Webapp-Startup.bat`) | [DSS-demo-readme], [DSS-demo-docker] |
| REST base | servlet `/services`: `/services/rest/validation/{validateSignature,getOriginalDocuments}`; `/services/rest/signature/one-document/{getDataToSign,signDocument,extendDocument,timestampDocument,getDataToBeCounterSigned,counterSignSignature}`; `/services/rest/signature/multiple-documents/...`; `/services/rest/certificate-validation`, `/services/rest/server-signing`, `/services/rest/timestamp-service/getTimestampResponse`, `/services/rest/signature/pades-external-cms`, `/services/rest/signature/external-cms`. The `/services` prefix comes from `WebSecurityConfiguration` matching `/services/rest/**` | [DSS-cxf], [DSS-rest] |
| Public demo | `https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo` | [DSS-demo-readme] |

## Inventory checklist

Flat list of implementable items. IDs are for roadmap traceability.

### Formats × levels (creation and augmentation)

- [x] F-01 CAdES-B-B (attached) — EN 319 122-1 §6.3
- [x] F-02 CAdES-B-B (detached) — EN 319 122-1 §4.5, §6.3
- [x] F-03 CAdES-B-B over a precomputed digest — EN 319 122-1 §5.1.2
- [ ] F-04 CAdES-B-T — EN 319 122-1 §6.3
- [ ] F-05 CAdES-B-LT — EN 319 122-1 §6.3
- [ ] F-06 CAdES-B-LTA (`archive-time-stamp-v3` + `ats-hash-index-v3`) — EN 319 122-1 §5.5, §6.3
- [ ] F-07 CAdES-E-BES / E-EPES / E-T / E-A — EN 319 122-2 §4.3
- [ ] F-08 CAdES-E-C / E-X (T1, T2) / E-X-Long / E-X-L — EN 319 122-2 Annex A
- [ ] F-09 XAdES-B-B enveloped — EN 319 132-1 §6.3; XMLDSig 1.1
- [ ] F-10 XAdES-B-B enveloping — EN 319 132-1 §6.3
- [ ] F-11 XAdES-B-B detached (external) — EN 319 132-1 §6.3
- [ ] F-12 XAdES-B-B internally detached — DSS doc §4.1.4; XMLDSig 1.1
- [ ] F-13 XAdES with signed `ds:Manifest` — EN 319 132-1 §6.3 (bb)
- [ ] F-14 XAdES-B-T — EN 319 132-1 §6.3
- [ ] F-15 XAdES-B-LT (incl. `TimeStampValidationData`) — EN 319 132-1 §5.5.1, §6.3
- [ ] F-16 XAdES-B-LTA (`ArchiveTimeStamp` v1.4.1, not-distributed and distributed cases) — EN 319 132-1 §5.5.2
- [ ] F-17 XAdES `RenewedDigestsV2` — EN 319 132-1 §5.5.3
- [ ] F-18 XAdES-E-BES / E-EPES / E-T / E-A and E-C / E-X / E-X-Long / E-X-L — EN 319 132-2
- [ ] F-19 PAdES-B-B (`ETSI.CAdES.detached`, `/M`, no `signing-time`) — EN 319 142-1 §6.3
- [ ] F-20 PAdES-B-T via signature TST — EN 319 142-1 §6.3 (n)
- [ ] F-21 PAdES-B-T via document time stamp — EN 319 142-1 §5.4.3, (n)
- [ ] F-22 PAdES-B-LT (DSS; optional VRI) — EN 319 142-1 §5.4.2, §6.3
- [ ] F-23 PAdES-B-LTA (DocTimeStamp `ETSI.RFC3161`) — EN 319 142-1 §5.4.3, §6.3
- [ ] F-24 PAdES on PDF 2.0 (ISO 32000-2) — draft EN 319 142-1 V1.3.0 §4.1, §5.6.2–5.6.3
- [ ] F-25 PAdES CMS profile (`adbe.pkcs7.detached`) — EN 319 142-2 §4
- [ ] F-26 PAdES-E-BES / E-EPES / E-LTV — EN 319 142-2 §5
- [ ] F-27 XAdES in PDF (embedded XML, XFA) — EN 319 142-2 §6
- [ ] F-28 PAdES-DTS document time stamp only — TS 119 142-3
- [ ] F-29 JAdES-B-B compact serialization — TS 119 182-1 §4, §6.3
- [ ] F-30 JAdES-B-B flattened JSON — TS 119 182-1 §4
- [ ] F-31 JAdES-B-B general JSON (multiple signatures) — TS 119 182-1 §4; RFC 7515 §7.2
- [ ] F-32 JAdES detached payload, `sigD` HttpHeaders / ObjectIdByURI / ObjectIdByURIHash — TS 119 182-1 §5.2.8
- [ ] F-33 JAdES unencoded payload `b64:false` — TS 119 182-1 §5.1.10; RFC 7797
- [ ] F-34 JAdES-B-T (`sigTst`) — TS 119 182-1 §5.3.4
- [ ] F-35 JAdES-B-LT (`xVals`, `rVals`, `tstVD`, `anyValData`) — TS 119 182-1 §5.3.5–5.3.6.1
- [ ] F-36 JAdES-B-LTA (`arcTst`, base64url and clear-JSON imprint) — TS 119 182-1 §5.3.6.2
- [ ] F-37 JAdES legacy reference components (`xRefs`, `rRefs`, `sigRTst`, `rfsTst`, `axRefs`, `arRefs`) — TS 119 182-1 Annex A
- [ ] F-38 JAdES with mandatory `x5c` (EU public sector) — CIR 2026/248 Annex I
- [ ] F-39 JAdES `iat` mandatory, `sigT` prohibited (from 2025-07-15) — TS 119 182-1 §5.1.11, §5.2.1
- [ ] F-40 ASiC-S + CAdES, B-B…B-LTA — EN 319 162-1 §5.3.2.2
- [ ] F-41 ASiC-S + XAdES, B-B…B-LTA — EN 319 162-1 §5.3.2.3
- [ ] F-42 ASiC-E + XAdES, B-B…B-LTA (`manifest.xml`) — EN 319 162-1 §5.3.3
- [ ] F-43 ASiC-E + CAdES (`ASiCManifest`) — EN 319 162-2 §4.3.1; CIR 2026/248 Annex I
- [ ] F-44 ASiC-S time assertion (`timestamp.tst`) + `ASiCArchiveManifest` — EN 319 162-1 §4.3.4; 162-2 §4.2.1
- [ ] F-45 ASiC-E time assertion — EN 319 162-2 §4.3.2
- [ ] F-46 ASiC with evidence records (`.ers`, `.xml`) — EN 319 162-1 §4.3.3.2
- [ ] F-47 ERS in CAdES — TS 119 122-3
- [ ] F-48 ERS in XAdES — TS 119 132-3
- [ ] F-49 CB-AdES (CBOR/COSE) baseline — TS 119 152-1 (new, 2026-03)
- [ ] F-50 FacturaE (XAdES-EPES enveloped, policy v3.1/3.0, roles) — FacturaE policy v3.1 §1
- [ ] F-51 FacturaE long-term (XAdES-X-L) — FacturaE policy v3.1 §2
- [ ] F-52 AGE policy EPES (XAdES, CAdES, PAdES) with OID `…2.1.9` and its hash — AGE policy v1.9 §2.6, §3.1. CAdES is done (M2); XAdES and PAdES come in M11 and M8
- [x] F-53 Bare CMS/PKCS#7 and raw PKCS#1 (`NONE`) as in AutoFirma — AutoFirma `AOSignConstants`

### Legacy forms (validation and augmentation)

- [ ] L-01 TS 101 733 CAdES-BES/EPES/T/C/X/X-L/A — TS 101 733 V2.2.1
- [ ] L-02 TS 101 903 XAdES (namespaces 1.1.1, 1.2.2, 1.3.2, 1.4.1) — TS 101 903 V1.4.2; AutoFirma `XAdESConstants`
- [ ] L-03 PAdES Basic `adbe.pkcs7.detached` / `adbe.pkcs7.sha1` — TS 102 778-2
- [ ] L-04 ISO 32000-1 PKCS#1 signatures (`adbe.x509.rsa_sha1`, `/Cert`) — EN 319 142-1 Table 1 (i)
- [ ] L-05 TS 103 171/172/173/174 baseline v2 (B, T, LT, LTA levels) — CIR 2026/248 Annex II
- [ ] L-06 Deprecated CAdES attributes (`other-signing-certificate`, `signer-attributes`, `archive-time-stamp` v2, `long-term-validation`, `ats-hash-index`) — EN 319 122-1 Annex A.2
- [ ] L-07 Deprecated XAdES properties (v1 SigningCertificate, SignerRole, SignatureProductionPlace, RefsV1, ArchiveTimeStamp 1.3.2, RenewedDigests) — EN 319 132-1 Annex A.2, Annex D
- [ ] L-08 New unsigned attributes added to legacy signatures follow the current EN — EN 319 122-1 §6.4; 132-1 §6.4; 142-1 §6.4

### Operations

- [x] O-01 Two-phase signing: data-to-sign out, signature value in, for every format — ADR-0001; EN 319 102-1 §4.2.6–4.2.8 (DTBS, DTBSF, DTBSR)
- [ ] O-02 CAdES co-sign (parallel SignerInfo) — EN 319 122-1 §4.4
- [ ] O-03 XAdES co-sign (sibling signatures) — EN 319 162-1 §4.3.3.2
- [ ] O-04 JAdES co-sign (general JSON) — RFC 7515 §7.2
- [ ] O-05 PAdES additional signature (new field, incremental update) — EN 319 142-1 §4.1(a)
- [ ] O-06 ASiC co-sign (more signatures in -S, more signature files in -E) — EN 319 162-1 §4.3–4.4
- [ ] O-07 CAdES countersignature (recursive; of any signatures the caller picks from the signer tree) — EN 319 122-1 §5.2.7
- [ ] O-08 XAdES enveloped countersignature (`CounterSignature`) — EN 319 132-1 §5.2.7.2
- [ ] O-09 XAdES detached countersignature (`ds:Reference/@Type`) — EN 319 132-1 §5.2.7.1
- [ ] O-10 JAdES `cSig` — TS 119 182-1 §5.3.2
- [ ] O-11 Augment B-B→B-T (all formats) — EN 319 102-1 §4.3.3
- [ ] O-12 Augment →B-LT (all formats) — EN 319 102-1 §4.3.4
- [ ] O-13 Augment →B-LTA (all formats) — EN 319 102-1 §4.3.5
- [ ] O-14 Archive time stamp renewal (repeatable) — EN 319 122-1 (s); 132-1 (aa); 182-1 (m); 142-1 §5.4.1
- [ ] O-15 Preserve the DSS contents of earlier revisions on PDF update — EN 319 142-1 §5.4.1
- [ ] O-16 PDF certification signature with DocMDP P=1/2/3 — EN 319 142-1 §5.4.2.3 note; ISO 32000-1 §12.8.2.2
- [ ] O-17 PDF approval signature; DocMDP checks before signing a certified PDF — ISO 32000-1 §12.8.2.2
- [ ] O-18 PDF visible signature appearance (rubric image, text, page, position, rotation) — ISO 32000-1 §12.7.4.5 (UNVERIFIED); AutoFirma `PdfExtraParams`
- [ ] O-19 PDF invisible signature — ISO 32000-1 (UNVERIFIED clause)
- [ ] O-20 Reserved `/Contents` size for later time stamps — EN 319 142-1 Table 1 (q)
- [ ] O-21 PDF encryption applied before signing (encrypted PDFs, owner and user passwords) — EN 319 142-1 §5.5
- [ ] O-22 PDF extensions dictionary `/ESIC` (1.7 only) — EN 319 142-1 §5.6
- [ ] O-23 Batch signing (one key, many documents) — AutoFirma batch modules
- [ ] O-24 Shadow-attack and form-modification checks before co-signing a PDF — AutoFirma `PdfExtraParams`

### Shared building blocks

- [x] B-01 CMS SignedData encode/decode, DER signed attributes — RFC 5652; EN 319 122-1 §4.7
- [x] B-02 ESS signing-certificate v1/v2 — RFC 5035; EN 319 122-1 §5.2.2
- [x] B-03 CMS algorithm protection — RFC 6211
- [x] B-04 content-hints, mime-type, content-reference, content-identifier — EN 319 122-1 §5.2.4, §5.2.11–12
- [ ] B-05 signer-location / SignatureProductionPlaceV2 / sigPl — 122-1 §5.2.5; 132-1 §5.2.5; 182-1 §5.2.4
- [ ] B-06 Signer attributes: claimed, certified (attribute certs), signed assertions (incl. SAML) — 122-1 §5.2.6; 132-1 §5.2.6; 182-1 §5.2.5
- [ ] B-07 Commitment types (6 ETSI OIDs and URIs, plus qualifiers) — TS 119 172-1 Annex B
- [x] B-08 Signature policy identifier, hash and qualifiers (SPURI, user notice, doc spec), implied policy — 122-1 §5.2.9; 132-1 §5.2.9; 182-1 §5.2.7
- [ ] B-09 Signature policy store — 122-1 §5.2.10; 132-1 §5.2.10; 182-1 `sigPSt`
- [ ] B-10 Machine-readable policies (XML, ASN.1) — TS 119 172-2, -3; TR 102 038, TR 102 272
- [ ] B-11 Content / data-object time stamps — 122-1 §5.2.8; 132-1 §5.2.8; 182-1 `adoTst`
- [ ] B-12 RFC 3161 client (request: nonce, reqPolicy, certReq; response checks) — RFC 3161; RFC 5816; EN 319 422 §4
- [ ] B-13 TST parsing and validation (ESSCertID(v2), accuracy, policy, qualified QC statement) — EN 319 422 §5, §9; EN 319 102-1 §5.4
- [ ] B-14 OCSP client and response parsing (OCSPResponse vs BasicOCSPResponse) — RFC 6960; EN 319 142-1 §5.4.2.2
- [ ] B-15 CRL fetch and parse — RFC 5280 §5
- [ ] B-16 OCSP and CRL in CMS `RevocationInfoChoices` — RFC 5940; EN 319 122-1 §5.4
- [ ] B-17 Certificate path building (AIA fetch, included certs, TL anchors) — RFC 5280 §4.2.2.1; EN 319 122-1 §6.3 (b–d)
- [ ] B-18 X.509 path validation — RFC 5280 §6; EN 319 102-1 §5.2.6
- [ ] B-19 XML parser preserving the bytes needed for C14N — XMLDSig 1.1
- [ ] B-20 C14N 1.0, C14N 1.1, Exclusive C14N (± comments) — EN 319 132-1 (d)
- [ ] B-21 Transforms: enveloped-signature, base64, XPath, XPath Filter 2.0, XSLT, OOXML relationship — EN 319 132-1 (g)
- [ ] B-22 XML algorithm URIs — RFC 6931, RFC 9231; TS 119 312 §10.3
- [ ] B-23 PDF parser and writer: xref and xref streams, object streams, incremental updates — ISO 32000-1 §7.5
- [ ] B-24 PDF signature dictionary, ByteRange, `/Contents` placeholder — ISO 32000-1 §12.8.1; EN 319 142-1 Table 1
- [ ] B-25 PDF DSS and VRI dictionaries — EN 319 142-1 §5.4.2
- [ ] B-26 PDF DocTimeStamp — EN 319 142-1 §5.4.3
- [ ] B-27 PDF hash and curve extensions (SHA-3, EdDSA, Brainpool) — ISO/TS 32001, ISO/TS 32002
- [ ] B-28 PDF/A awareness when signing — EN 319 142-2 A.6–A.7
- [ ] B-29 JWS compact and JSON serializations — RFC 7515
- [ ] B-30 JWS unencoded payload — RFC 7797
- [ ] B-31 JWA algorithm identifiers (RS*, PS*, ES*, EdDSA) — RFC 7518; RFC 8037
- [ ] B-32 ZIP reader and writer per ISO/IEC 21320-1, `mimetype` first and stored — EN 319 162-1 §5.3.1, A.1
- [ ] B-33 ASiCManifest / ASiCArchiveManifest XML — EN 319 162-1 A.4, A.7
- [ ] B-34 Evidence record syntax (ERS, XMLERS) — RFC 4998; RFC 6283
- [ ] B-35 MIME / S/MIME wrapping — EN 319 122-1 Annex E (informative)
- [x] B-36 Injected time and randomness, reproducible output — rades AGENTS.md (design constraint)

### Algorithms

- [x] A-01 SHA-256/384/512 — TS 119 312 §5.1
- [x] A-02 SHA3-256/384/512 — TS 119 312 §5.1
- [ ] A-03 SHA-1, SHA-224 (verification of legacy only) — TS 119 312 Annex D
- [x] A-04 RSA PKCS#1 v1.5 (legacy) — TS 119 312 §6.2.2.1
- [x] A-05 RSA-PSS (recommended; parameters in CMS, XML, JOSE) — TS 119 312 §6.2.2.1; RFC 8017
- [ ] A-06 ECDSA P-256/384/521, brainpoolP256/384/512r1, FRP256v1 — TS 119 312 §6.2.2.3 Table 3 (P-256/384/521 done in M1; brainpool and FRP256v1 in M13)
- [ ] A-07 EdDSA Ed25519, Ed448 — TS 119 312 §6.2.2.4; RFC 8032
- [ ] A-08 DSA (verification) — TS 119 312 §6.2.2.2
- [ ] A-09 ML-DSA (pure) verification; creation optional — TS 119 312 §6.2.2.5, Annex A
- [ ] A-10 SLH-DSA (pure in CMS) verification — TS 119 312 §6.2.2.6, Annex A
- [ ] A-11 LMS / XMSS verification (TSTs) — TS 119 312 §6.2.2.7, A.9
- [ ] A-12 Cryptographic constraints by date (RSA < 3000 bits after 2026-12-31; Annex D end dates) — TS 119 312 §8.4, Annex D
- [x] A-13 Reject MD5 as a digest — EN 319 122-1 §6.2.1 (and the same clause in the other ENs)

### Validation

- [ ] V-01 Format checking per format — EN 319 102-1 §5.2.2
- [ ] V-02 Signing certificate identification — EN 319 102-1 §5.2.3
- [ ] V-03 Validation context initialization (policy and constraints) — EN 319 102-1 §5.2.4
- [ ] V-04 Revocation freshness checker — EN 319 102-1 §5.2.5
- [ ] V-05 X.509 certificate validation — EN 319 102-1 §5.2.6
- [ ] V-06 Cryptographic verification (incl. reference and digest checks) — EN 319 102-1 §5.2.7
- [ ] V-07 Signature acceptance validation (AdES attributes) — EN 319 102-1 §5.2.8
- [ ] V-08 Basic signature validation process — EN 319 102-1 §5.3
- [ ] V-09 Time-stamp validation building block — EN 319 102-1 §5.4
- [ ] V-10 Validation of signatures with time and with LT material — EN 319 102-1 §5.5
- [ ] V-11 Past certificate validation — EN 319 102-1 §5.6.2.1
- [ ] V-12 Validation time sliding — EN 319 102-1 §5.6.2.2
- [ ] V-13 POE extraction — EN 319 102-1 §5.6.2.3
- [ ] V-14 Past signature validation — EN 319 102-1 §5.6.2.4
- [ ] V-15 LTA validation process — EN 319 102-1 §5.6.3
- [ ] V-16 Indications TOTAL-PASSED / TOTAL-FAILED / INDETERMINATE and every sub-indication — EN 319 102-1 §5.1.3 Tables 5–6
- [ ] V-17 Validation constraints model (X.509, cryptographic, signature elements) — EN 319 102-1 §5.1.4; TS 119 172-1 A.4
- [ ] V-18 ETSI validation report (XML) — TS 119 102-2 V1.4.1
- [ ] V-19 Trusted list parsing and XAdES signature verification — TS 119 612 V2.4.1
- [ ] V-20 LOTL → national TL authentication (pivots, signing-cert announcements) — TS 119 615 §4.1–4.2
- [ ] V-21 Trust service lookup for a certificate (with history) — TS 119 615 §4.3
- [ ] V-22 EU qualified certificate determination — TS 119 615 §4.4
- [ ] V-23 QSCD determination — TS 119 615 §4.5
- [ ] V-24 Qualified time-stamp determination — TS 119 615 §4.7
- [ ] V-25 QCStatements parsing (QcCompliance, QcSSCD, QcType, QcLimitValue, QcRetentionPeriod, QcPDS, QcCClegislation, QcQSCDlegislation, QcIdentMethod) — EN 319 412-5 V2.6.1
- [ ] V-26 EU applicability rules realTimeReq / realTimeNotReq — TS 119 172-4 V1.2.1 (V1.1.1 in CIR 2025/1945)
- [ ] V-27 Legal QES/AdES-QC validation profile (eitherCheck, 24 h freshness) — CIR 2025/1945 Annex I–II
- [ ] V-28 PAdES-specific: ByteRange coverage, revision analysis, DocMDP/FieldMDP, VRI keying — EN 319 142-1 §5.4; ISO 32000-1 §12.8
- [ ] V-29 Signature policy checking (hash match, policy-specific rules for AGE and FacturaE) — EN 319 102-1 §5.2.8; AGE policy §3
- [ ] V-30 Validation application requirements — TS 119 101 V1.1.1 (CIR 2025/1945 REQ-4.3-02)

### Remote and services (optional scope)

- [ ] R-01 Remote signing client (two-phase over `signHash`) — TS 119 432 V1.3.1; CSC API 2.2.0.0
- [ ] R-02 Remote validation/augmentation protocol client — TS 119 442 V1.1.1

### Conformance and oracles

- [ ] C-01 CAdES baseline interop cases `CAdES/BB…Aug` — TS 119 124-2 (B-B in M1; the rest per level, `docs/cades-bb-matrix.md`)
- [ ] C-02 CAdES extended interop cases — TS 119 124-3
- [ ] C-03 CAdES baseline conformance assertions — TS 119 124-4 (B-B in M1; the rest per level, `docs/cades-bb-matrix.md`)
- [ ] C-04 CAdES extended conformance assertions — TS 119 124-5
- [ ] C-05 XAdES interop (baseline, extended) — TS 119 134-2, -3
- [ ] C-06 XAdES conformance (baseline, extended) — TS 119 134-4, -5 (V2.1.1)
- [ ] C-07 PAdES interop (baseline V2.1.1, additional) — TS 119 144-2, -3
- [ ] C-08 PAdES conformance — TS 119 144-4, -5
- [ ] C-09 ASiC interop (baseline V2.1.1, additional) — TS 119 164-2, -3
- [ ] C-10 ASiC conformance — TS 119 164-4, -5
- [ ] C-11 JAdES: no ETSI test specification; derive from TS 119 182-1 Table 1 — etsi.org/deliver listing
- [x] C-12 ETSI Signatures Conformance Checker run per format — signatures-conformance-checker.etsi.org
- [x] C-13 DSS 6.5.x validation in CI (REST `validateSignature`, simple and ETSI reports) — DSS docs §15.1; `CXFConfig`
- [ ] C-14 AutoFirma round-trip (AutoFirma signs, rades validates, and the reverse) — ADR-0001 (AutoFirma verifies rades since M0; rades validates AutoFirma from M13)
- [ ] C-15 ETSI Plugtests participation (CB-AdES 2026; future AdES/LTA events) — ETSI CTI

## References

[eIDAS-cons]: https://publications.europa.eu/resource/celex/02014R0910-20241018 "Regulation (EU) No 910/2014, consolidated 2024-10-18 (ELI http://data.europa.eu/eli/reg/2014/910/oj)"
[eIDAS2]: http://data.europa.eu/eli/reg/2024/1183/oj
[CID-2015-1506]: http://data.europa.eu/eli/dec_impl/2015/1506/oj
[CIR-2026-248]: http://data.europa.eu/eli/reg_impl/2026/248/oj
[CIR-2025-1945]: https://publications.europa.eu/resource/celex/32025R1945
[CIR-2025-1943]: https://publications.europa.eu/resource/celex/32025R1943
[CIR-2025-1944]: https://publications.europa.eu/resource/celex/32025R1944
[CIR-2025-1946]: https://publications.europa.eu/resource/celex/32025R1946
[CIR-2025-2160]: https://publications.europa.eu/resource/celex/32025R2160
[EN122-1]: https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
[EN122-2]: https://www.etsi.org/deliver/etsi_en/319100_319199/31912202/01.01.01_60/en_31912202v010101p.pdf
[TS122-3]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11912203/01.02.01_60/ts_11912203v010201p.pdf
[EN132-1]: https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
[EN132-2]: https://www.etsi.org/deliver/etsi_en/319100_319199/31913202/01.01.01_60/en_31913202v010101p.pdf
[TS132-3]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11913203/01.01.01_60/ts_11913203v010101p.pdf
[EN142-1]: https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
[EN142-1-draft]: https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.03.00_20/en_31914201v010300a.pdf
[EN142-2]: https://www.etsi.org/deliver/etsi_en/319100_319199/31914202/01.02.01_60/en_31914202v010201p.pdf
[TS142-3]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11914203/01.01.01_60/ts_11914203v010101p.pdf
[TS182-1]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf
[EN162-1]: https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf
[EN162-2]: https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf
[TS152-1]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf
[EN102-1]: https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf
[TS102-2]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf
[TS172-1]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11917201/01.01.01_60/ts_11917201v010101p.pdf
[TS172-2]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11917202/01.01.01_60/ts_11917202v010101p.pdf
[TS172-3]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11917203/01.01.01_60/ts_11917203v010101p.pdf
[TS172-4]: https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf
[TS312]: https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf
[TS612]: https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf
[TS615]: https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf
[EN412-5]: https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf
[EN422]: https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf
[TS432]: https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.03.01_60/ts_119432v010301p.pdf
[TS431-1]: https://www.etsi.org/deliver/etsi_ts/119400_119499/11943101/01.03.01_60/ts_11943101v010301p.pdf
[TS431-2]: https://www.etsi.org/deliver/etsi_ts/119400_119499/11943102/01.02.01_60/ts_11943102v010201p.pdf
[TS441]: https://www.etsi.org/deliver/etsi_ts/119400_119499/119441/01.03.01_60/ts_119441v010301p.pdf
[TS442]: https://www.etsi.org/deliver/etsi_ts/119400_119499/119442/01.01.01_60/ts_119442v010101p.pdf
[TS101]: https://www.etsi.org/deliver/etsi_ts/119100_119199/119101/01.01.01_60/ts_119101v010101p.pdf
[TS192]: https://www.etsi.org/deliver/etsi_ts/119100_119199/119192/01.02.01_60/ts_119192v010201p.pdf
[TS1x4]: https://www.etsi.org/deliver/etsi_ts/119100_119199/ "folders 11912402–05, 11913402–05, 11914402–05, 11916402–05; TRs under etsi_tr/119100_119199/1191x401"
[TS101733]: https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.02.01_60/
[TS101903]: https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/
[TS102778]: https://www.etsi.org/deliver/etsi_ts/102700_102799/ "folders 10277801–10277806"
[TS102918]: https://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/
[XMLDSig11]: https://www.w3.org/TR/xmldsig-core1/
[PDFA-32001]: https://pdfa.org/resource/iso-ts-32001/
[PDFA-32002]: https://pdfa.org/resource/iso-ts-32002/
[CSC]: https://cloudsignatureconsortium.org/resources/csc-api-v2-2/
[ETSI-SCC]: https://signatures-conformance-checker.etsi.org/pub/index.php
[EC-SCC]: https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/ETSI+Signature+Conformance+Checker
[ETSI-JAdES-PT]: https://www.etsi.org/events/1938-jades-remote-plugtests/
[ETSI-LTA-PT]: https://www.etsi.org/newsroom/press-releases/2333-future-confidence-inaugural-lta-signature-augmentation-and-validation-plugtests-focuses-on-long-term-archive-signatures/
[ETSI-CTI-ESI]: https://portal.etsi.org/CTI/Activities/ESI/Events.htm
[AGE-pol]: https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf
[BOE-NTI-2011]: https://www.boe.es/buscar/doc.php?id=BOE-A-2011-13171
[BOE-RD-203-2021]: https://www.boe.es/buscar/act.php?id=BOE-A-2021-5032
[FE-pol]: https://www.facturae.gob.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf
[AF-src]: https://github.com/ctt-gob-es/clienteafirma/tree/bd9254be70004be095b1251b5a4af15b9d392dd9
[AF-const]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-core/src/main/java/es/gob/afirma/core/signers/AOSignConstants.java
[AF-cst]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-core/src/main/java/es/gob/afirma/core/signers/CounterSignTarget.java
[AF-cli]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-simple/src/main/java/es/gob/afirma/standalone/CommandLineCommand.java
[AF-proto]: https://github.com/ctt-gob-es/clienteafirma/tree/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-core/src/main/java/es/gob/afirma/core/misc/protocol
[AF-policy]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-core/src/main/resources/policy.properties
[AF-facturae]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-crypto-xades/src/main/java/es/gob/afirma/signers/xades/AOFacturaESigner.java
[AF-cades-params]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-crypto-cades/src/main/java/es/gob/afirma/signers/cades/CAdESExtraParams.java
[AF-xades-params]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-crypto-xades/src/main/java/es/gob/afirma/signers/xades/XAdESExtraParams.java
[AF-pdf-params]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-crypto-pdf-common/src/main/java/es/gob/afirma/signers/pades/common/PdfExtraParams.java
[AF-pdfutil]: https://github.com/ctt-gob-es/clienteafirma/blob/bd9254be70004be095b1251b5a4af15b9d392dd9/afirma-crypto-pdf/src/main/java/es/gob/afirma/signers/pades/PdfUtil.java
[DSS-rel]: https://github.com/esig/dss/releases
[DSS-doc]: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html
[DSS-enum]: https://github.com/esig/dss/tree/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations
[DSS-rest]: https://github.com/esig/dss/blob/master/dss-signature-rest-client/src/main/java/eu/europa/esig/dss/ws/signature/rest/client/RestDocumentSignatureService.java "and dss-validation-rest-client/.../RestDocumentValidationService.java"
[DSS-cxf]: https://github.com/esig/dss-demonstrations/blob/master/dss-demo-webapp/src/main/java/eu/europa/esig/dss/web/config/CXFConfig.java
[DSS-demo-readme]: https://github.com/esig/dss-demonstrations/blob/master/README.md
[DSS-demo-docker]: https://github.com/esig/dss-demonstrations/blob/master/Dockerfile

RFCs cited by number resolve at `https://www.rfc-editor.org/rfc/rfcNNNN`: 2634, 2045, 3161, 3739, 4158, 4998, 5035, 5280, 5652, 5816, 5940, 6211, 6283, 6931, 6960, 7515, 7518, 7519, 7797, 8017, 8032, 8037, 8551, 9231.
