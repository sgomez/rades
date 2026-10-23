# CAdES B-B requirements matrix

The creation side of CAdES B-B, from ETSI TS 119 124-2 (`CAdES/BB`) and TS 119 124-4 (clause 5 assertions), as ADR-0001 asks. Each row names the test that covers it, or the milestone that will (`docs/roadmap.md`). Tests are `file::test` under `tests/`.

Obligation is that of a generator at B-B, from EN 319 122-1 §6.3 Table 1 and the CMS structure.

Rows of the negative cases `CAdES/BBN/1..11` are about validating a foreign signature: M13.

## TS 119 124-2: interoperability cases

| Case | Obligation | What it signs | Covered by |
| --- | --- | --- | --- |
| `CAdES/BB/1` | shall | The mandatory attributes only, the signer certificate embedded | `cades_bb::detached_rsa_sha256_matches_the_golden_vector`, `cades_bb::attached_rsa_sha256_matches_the_golden_vector`, `cades_bb::signed_attributes_are_those_of_cades_bb`, `cades_bb::the_signer_certificate_is_embedded_by_default`; DSS and AutoFirma judge the same files (`tests/cades/manifest.tsv`) |
| `CAdES/BB/2` | may | `signer-attributes-v2` with a certified attribute | M2 |
| `CAdES/BB/3` | may | `signer-attributes-v2` with a claimed attribute | M2 |
| `CAdES/BB/4` | may | Several independent signers | M4 |
| `CAdES/BB/5` | may | A countersignature | M4 |
| `CAdES/BB/6` | may | `signer-location` and `commitment-type-indication` | M2 |
| `CAdES/BB/7` | may | `content-time-stamp` | M3 |
| `CAdES/BB/8` | may | An explicit `signature-policy-identifier` | `cades_policy::the_age_policy_matches_the_golden_vector`, `cades_policy::the_age_policy_is_encoded_as_in_en_319_122_1`, `cades_policy::a_user_notice_is_encoded_as_in_en_319_122_1`, `cades_policy::a_document_specification_is_encoded_as_in_en_319_122_1`, `cades_policy::an_implied_policy_is_a_null`, `cades_policy::the_age_policy_signs_attached_content`, `cades_policy::the_age_policy_signs_a_precomputed_digest`, `cades_policy::the_age_policy_signs_with_ecdsa`, `cades_policy::the_policy_composes_with_the_optional_attributes_and_the_chain`; DSS and AutoFirma judge the same files (`tests/cades/manifest.tsv`) |
| `CAdES/BB/9` | shall if SHA-1 | SHA-1 and `signing-certificate` v1 | M13 (SHA-1 and creating v1 are out of scope) |

## TS 119 124-4: assertions on a generator

| Assertion | Obligation | Requirement | Covered by |
| --- | --- | --- | --- |
| `CAdES_BS/ALG/1` | shall | No MD5 as digest algorithm | `DigestAlgorithm` has no MD5; `cades_requirements::no_golden_vector_uses_md5` |
| `CAdES_BB/CTY/1` | shall | `content-type` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BS/CTY/1` | shall | `content-type` is `id-data` | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/MD/1` | shall | `message-digest` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/CMSV` | shall | `SignedData.version` present | `cades_requirements::the_signed_data_version_is_1_for_id_data_with_issuer_and_serial_identifiers` |
| `CAdES_BB/DAI` | shall | `digestAlgorithms` present | `cades_requirements::the_digest_algorithms_list_the_signers_digest` |
| `CAdES_BB/ECI` | shall | `encapContentInfo` present | `cades_requirements::the_encapsulated_content_is_id_data_and_carries_the_content_only_when_attached` |
| `CAdES_BB/SDC/1` | should | All certificates for path building embedded | `cades_bb::the_chain_is_embedded_on_request` |
| `CAdES_BB/SDC/2` | should | No duplicate certificates | `cades_requirements::a_certificate_given_twice_is_embedded_once` |
| `CAdES_BS/SDC/1` | shall | The signing certificate embedded | `cades_bb::the_signer_certificate_is_embedded_by_default` |
| `CAdES_BB/SDCRL/1`, `/2`, `/3` | may | Revocation values in `SignedData.crls` | M14 |
| `CAdES_BB/SI/1` | shall | One or more `SignerInfo` | `cades_requirements::a_signature_has_exactly_one_signer_info`; several signers: M4 |
| `CAdES_BB/STI/1` | shall | `signing-time` as UTCTime up to 2049, GeneralizedTime after | `cades_requirements::the_signing_time_is_a_utc_time_up_to_2049_and_a_generalized_time_from_2050`; the UTCTime bytes also in `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BS/STI/1` | shall | `signing-time` present | `cades_bb::signed_attributes_carry_content_type_digest_and_time` |
| `CAdES_BB/ESS/1`, `/3` | shall | `signing-certificate-v2` for a hash other than SHA-1 | `cades_bb::signing_certificate_v2_identifies_the_signer_certificate`, `cades_bb::signing_certificate_v2_hashes_with_the_signatures_digest` |
| `CAdES_BB/ESS/2` | shall if SHA-1 | `signing-certificate` v1 | M13 |
| `CAdES_BB/ESS/4` | should | No `issuerSerial` in `signing-certificate-v2` | Not followed on purpose: `issuerSerial` is included (spec #23); `cades_decode::signing_certificate_v2_is_read` pins it |
| `CAdES_BS/ESS/1` | shall | `signing-certificate-v2` in every `SignerInfo` | `cades_bb::signing_certificate_v2_identifies_the_signer_certificate` |
| `CAdES_BB/CS/1` | may | `countersignature` | M4 |
| `CAdES_BB/CR/1` | may | `content-reference` | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CI/1` | may | `content-identifier` | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CH/1` | should | `content-hints` | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::content_hints_without_description_is_the_content_type_alone` |
| `CAdES_BB/MT/1` | should | `mime-type` | `cades_bb::optional_attributes_are_encoded_as_in_en_319_122_1`, `cades_bb::optional_attributes_appear_only_when_set` |
| `CAdES_BB/CTI/1` | may | `commitment-type-indication` | M2 |
| `CAdES_BB/SL/1` | may | `signer-location` | M2 |
| `CAdES_BB/SA/1` | may | `signer-attributes-v2` | M2 |
| `CAdES_BB/CTS/1` | may | `content-time-stamp` | M3 |
| `CAdES_BB/SPID/1` | may | `signature-policy-identifier` | `cades_policy::the_age_policy_is_encoded_as_in_en_319_122_1`, `cades_policy::decode_returns_the_age_policy`, `cades_policy::decode_returns_each_shape_as_it_was_signed`, `cades_policy::an_autofirma_signature_with_exp_policy_firma_age_decodes_to_the_age_policy`, `cades_policy::a_malformed_policy_attribute_is_an_error_not_a_panic` |
| `CAdES_BB/SPS/1` | may | `signature-policy-store`, only with a `sigPolicyHash` | M2 |
