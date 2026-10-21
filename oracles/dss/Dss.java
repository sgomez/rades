///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 17+
//DEPS eu.europa.ec.joinup.sd-dss:dss-cades:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-validation:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-policy-jaxb:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-crl-parser-stream:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-cms-object:6.5.1
//DEPS org.slf4j:slf4j-nop:2.0.17

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Validates every signature in a manifest with DSS and fails on any verdict the manifest does not expect. */
public class Dss {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: Dss <policy> <trusted root> <signature directory>...");
            System.exit(2);
        }
        File policy = new File(args[0]);
        CommonCertificateVerifier verifier = offlineVerifier(Path.of(args[1]));
        List<String> mismatches = new ArrayList<>();
        int checked = 0;
        for (int i = 2; i < args.length; i++) {
            Path dir = Path.of(args[i]);
            for (String line : Files.readAllLines(dir.resolve("manifest.tsv"))) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] entry = line.trim().split("\\s+");
                if (entry.length != 3) {
                    throw new IllegalArgumentException("manifest line is not `file indication level`: " + line);
                }
                Path signature = dir.resolve(entry[0]);
                Verdict verdict = verdict(signature.toFile(), policy, verifier);
                String expected = entry[1] + " " + entry[2];
                checked++;
                if (verdict.outcome().equals(expected)) {
                    System.out.println("ok       " + signature + ": " + verdict.outcome());
                } else {
                    System.out.println("MISMATCH " + signature + ": expected " + expected + ", got " + verdict.outcome()
                            + " (" + verdict.detail() + ")");
                    mismatches.add(signature.toString());
                }
            }
        }
        if (!mismatches.isEmpty()) {
            System.err.println("DSS disagrees with the manifest on: " + String.join(", ", mismatches));
            System.exit(1);
        }
        System.out.println("DSS agrees with the manifest on " + checked + " signatures");
    }

    private static CommonCertificateVerifier offlineVerifier(Path root) {
        CertificateToken token = DSSUtils.loadCertificate(root.toFile());
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(token);
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);
        return verifier;
    }

    private record Verdict(String outcome, String detail) {}

    private static Verdict verdict(File signature, File policy, CommonCertificateVerifier verifier) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(signature));
        validator.setCertificateVerifier(verifier);
        SimpleReport report = validator.validateDocument(policy).getSimpleReport();
        List<String> ids = report.getSignatureIdList();
        if (ids.size() != 1) {
            return new Verdict(ids.size() + " signatures", "the manifest expects exactly one per file");
        }
        String id = ids.get(0);
        return new Verdict(
                report.getIndication(id) + " " + report.getSignatureFormat(id),
                report.getSubIndication(id) + ": " + report.getAdESValidationErrors(id).stream().map(m -> m.getValue()).toList());
    }
}
