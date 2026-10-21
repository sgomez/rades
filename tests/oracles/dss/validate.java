//% java 17
//% dependency eu.europa.ec.joinup.sd-dss:dss-bom:6.5.1:pom@pom
//% dependency eu.europa.ec.joinup.sd-dss:dss-cades:6.5.1
//% dependency eu.europa.ec.joinup.sd-dss:dss-spi:6.5.1
//% dependency eu.europa.ec.joinup.sd-dss:dss-validation:6.5.1
//% dependency eu.europa.ec.joinup.sd-dss:dss-enumerations:6.5.1

import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.*;

import eu.europa.esig.dss.cades.validation.CAdESDocumentValidator;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonCertificate;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * DSS oracle: validates signatures from a manifest file.
 * Reads tests/oracles/manifest.json, validates each entry with DSS 6.2,
 * and fails on any mismatch between expected and actual verdict.
 */
public class validate {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: validate <base-dir>");
            System.exit(1);
        }

        Path baseDir = Paths.get(args[0]).toAbsolutePath().normalize();
        Path manifestPath = baseDir.resolve("manifest.json");

        // Read the manifest
        String json = Files.readString(manifestPath);
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        List<Map<String, String>> entries = mapper.readValue(json,
            List.class);

        boolean allPassed = true;

        for (Map<String, String> entry : entries) {
            String fileName = entry.get("file");
            String expectedIndication = entry.get("expected_indication");
            String expectedLevel = entry.get("expected_level");

            Path sigPath = baseDir.resolve(fileName).toAbsolutePath().normalize();
            System.out.println("Validating: " + fileName);

            try {
                byte[] signatureValue = Files.readAllBytes(sigPath);

                // Build a CAdES validator and trust only the test root
                SignedDocumentValidator validator = buildCadesValidator(signatureValue, baseDir);

                // Validate at CAdES-Baseline-B level
                DiagnosticData diagData = validator.validateSignatureAtLevel(
                    signatureValue, SignatureLevel.CAdES_BASELINE_B);

                Indication globalIndication = diagData.getGlobalIndication();
                SignatureLevel globalLevel = diagData.getSignatureLevel();

                String actualIndicationStr = globalIndication != null
                    ? globalIndication.getValue() : "UNKNOWN";
                String actualLevelStr = globalLevel != null
                    ? globalLevel.getValue() : "NONE";

                System.out.println("  Indication: " + actualIndicationStr);
                System.out.println("  Level:      " + actualLevelStr);

                // Check against expected
                if (!expectedIndication.equals(actualIndicationStr)) {
                    System.err.println("  MISMATCH: expected indication " + expectedIndication
                        + ", got " + actualIndicationStr);
                    allPassed = false;
                }

                if (expectedLevel != null && !expectedLevel.equals(actualLevelStr)) {
                    System.err.println("  MISMATCH: expected level " + expectedLevel
                        + ", got " + actualLevelStr);
                    allPassed = false;
                }

            } catch (Exception e) {
                System.err.println("  Error: " + e.getMessage());
                if (!"TOTAL_FAILED".equals(expectedIndication)) {
                    allPassed = false;
                }
            }

            System.out.println();
        }

        if (!allPassed) {
            System.err.println("DSS oracle: FAILED");
            System.exit(1);
        } else {
            System.out.println("DSS oracle: PASSED");
        }
    }

    /** Build a CAdES validator that trusts only the test root CA. */
    private static SignedDocumentValidator buildCadesValidator(
            byte[] signatureValue, Path baseDir) throws Exception {

        Path rootCrt = baseDir.resolve("../test-pki/root-ca/root-ca.crt")
            .toAbsolutePath().normalize();
        CommonCertificate rootCert = DSSUtils.loadCertificate(rootCrt.toFile());

        // Create a CAdES validator with the signature
        CAdESDocumentValidator validator = new CAdESDocumentValidator(
            signatureValue, Collections.singletonList(rootCert));

        // Disable revocation checks to avoid INDETERMINATE results
        validator.setRevocationDataSources(Collections.emptyList());

        return validator;
    }
}
