# CAdES B-B requirements matrix

The creation side of CAdES B-B, from ETSI TS 119 124-2 (`CAdES/BB`) and TS 119 124-4 (clause 5 assertions), as ADR-0001 asks. Each row names the test that covers it, or the milestone that will (`docs/roadmap.md`). Tests are `file::test` under `tests/`.

Rows of the negative cases `CAdES/BBN/1..11` are about validating a foreign signature: M13.

## TS 119 124-2: interoperability cases

| Case | What it signs | Covered by |
| --- | --- | --- |
| `CAdES/BB/1` | The mandatory attributes only, the signer certificate embedded | `cades_bb::detached_rsa_sha256_matches_the_golden_vector`, `cades_bb::attached_rsa_sha256_matches_the_golden_vector`, `cades_bb::signed_attributes_are_those_of_cades_bb`, `cades_bb::the_signer_certificate_is_embedded_by_default`; DSS and AutoFirma judge the same files (`tests/cades/manifest.tsv`) |
| `CAdES/BB/2` | `signer-attributes-v2` with a certified attribute | M2 |
| `CAdES/BB/3` | `signer-attributes-v2` with a claimed attribute | M2 |
| `CAdES/BB/4` | Several independent signers | M4 |
| `CAdES/BB/5` | A countersignature | M4 |
| `CAdES/BB/6` | `signer-location` and `commitment-type-indication` | M2 |
| `CAdES/BB/7` | `content-time-stamp` | M3 |
| `CAdES/BB/8` | An explicit `signature-policy-identifier` | `cades_policy::the_age_policy_matches_the_golden_vector`, `cades_policy::the_age_policy_is_encoded_as_in_en_319_122_1`; DSS and AutoFirma judge the same files (`tests/cades/manifest.tsv`) |
| `CAdES/BB/9` | SHA-1 and `signing-certificate` v1 | M13 (SHA-1 and creating v1 are out of scope) |

## TS 119 124-4: assertions on a generator

| Assertion | Requirement | Covered by |
| --- | --- | --- |
| `CAdES_BS/ALG/1` | No MD5 as digest algorithm | `DigestAlgorithm` has no MD5; `cades_requirements::no_golden_vector_uses_md5` |
| `CAdES_BB/CTY/1` | `content-type` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BS/CTY/1` | `content-type` is `id-data` | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/MD/1` | `message-digest` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/CMSV` | `SignedData.version` present | `cades_requirements::the_signed_data_version_is_1_for_id_data_with_issuer_and_serial_identifiers` |
| `CAdES_BB/DAI` | `digestAlgorithms` present | `cades_requirements::the_digest_algorithms_list_the_signers_digest` |
| `CAdES_BB/ECI` | `encapContentInfo` present | `cades_requirements::the_encapsulated_content_is_id_data_and_carries_the_content_only_when_attached` |
| `CAdES_BB/SDC/1` | All certificates for path building embedded (recommended) | `cades_bb::the_chain_is_embedded_on_request` |
| `CAdES_BB/SDC/2` | No duplicate certificates (recommended) | `cades_requirements::a_certificate_given_twice_is_embedded_once` |
| `CAdES_BS/SDC/1` | The signing certificate embedded | `cades_bb::the_signer_certificate_is_embedded_by_default` |
| `CAdES_BB/SDCRL/1`, `/2`, `/3` | Revocation values in `SignedData.crls` (permitted) | M14 |
| `CAdES_BB/SI/1` | One or more `SignerInfo` | `cades_requirements::a_signature_has_exactly_one_signer_info`; several signers: M4 |
| `CAdES_BB/STI/1` | `signing-time` as UTCTime up to 2049, GeneralizedTime after | `cades_requirements::the_signing_time_is_a_utc_time_up_to_2049_and_a_generalized_time_from_2050`; the UTCTime bytes also in `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BS/STI/1` | `signing-time` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/ESS/1`, `/3` | `signing-certificate-v2` for a hash other than SHA-1 | `cades_bb::signing_certificate_v2_identifies_the_signer_certificate`, `cades_bb::signing_certificate_v2_hashes_with_the_signatures_digest` |
| `CAdES_BB/ESS/2` | `signing-certificate` v1 when SHA-1 is used | M13 |
| `CAdES_BB/ESS/4` | No `issuerSerial` in `signing-certificate-v2` (recommended) | Not followed on purpose: `issuerSerial` is included (spec #23); `cades_decode::signing_certificate_v2_is_read` pins it |
| `CAdES_BS/ESS/1` | `signing-certificate-v2` in every `SignerInfo` | `cades_bb::signing_certificate_v2_identifies_the_signer_certificate` |
| `CAdES_BB/CS/1` | `countersignature` (permitted) | M4 |
| `CAdES_BB/CR/1` | `content-reference` (permitted) | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CI/1` | `content-identifier` (permitted) | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CH/1` | `content-hints` (permitted) | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::content_hints_without_description_is_the_content_type_alone` |
| `CAdES_BB/MT/1` | `mime-type` (permitted) | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CTI/1` | `commitment-type-indication` (permitted) | M2 |
| `CAdES_BB/SL/1` | `signer-location` (permitted) | M2 |
| `CAdES_BB/SA/1` | `signer-attributes-v2` (permitted) | M2 |
| `CAdES_BB/CTS/1` | `content-time-stamp` (permitted) | M3 |
| `CAdES_BB/SPID/1` | `signature-policy-identifier` (permitted) | `cades_policy::the_age_policy_is_encoded_as_in_en_319_122_1`, `cades_policy::decode_returns_the_age_policy` |
| `CAdES_BB/SPS/1` | `signature-policy-store` (permitted) | M2 |
