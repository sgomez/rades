///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 17+
//DEPS eu.europa.ec.joinup.sd-dss:dss-cades:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-validation:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-policy-jaxb:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-crl-parser-stream:6.5.1
//DEPS eu.europa.ec.joinup.sd-dss:dss-cms-object:6.5.1
//DEPS org.slf4j:slf4j-nop:2.0.17

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
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
        if (args.length < 4) {
            System.err.println("usage: Dss <policy> <trusted root> <intermediate CA> <signature directory>...");
            System.exit(2);
        }
        File policy = new File(args[0]);
        CommonCertificateVerifier verifier = offlineVerifier(Path.of(args[1]), Path.of(args[2]));
        List<String> mismatches = new ArrayList<>();
        int checked = 0;
        for (int i = 3; i < args.length; i++) {
            Path dir = Path.of(args[i]);
            for (String line : Files.readAllLines(dir.resolve("manifest.tsv"))) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] entry = line.trim().split("\\s+");
                if (entry.length != 3 && entry.length != 4) {
                    throw new IllegalArgumentException("manifest line is not `file indication level [content]`: " + line);
                }
                Path signature = dir.resolve(entry[0]);
                DSSDocument content = entry.length == 4 ? detachedContent(dir, entry[3]) : null;
                Verdict verdict = verdict(signature.toFile(), content, policy, verifier);
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

    private static CommonCertificateVerifier offlineVerifier(Path root, Path intermediate) {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(root.toFile()));
        // Signatures that embed only the signer certificate need the intermediate to build the chain.
        CommonCertificateSource adjunct = new CommonCertificateSource();
        adjunct.addCertificate(DSSUtils.loadCertificate(intermediate.toFile()));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setAdjunctCertSources(adjunct);
        verifier.setAIASource(null);
        verifier.setOcspSource(null);
        verifier.setCrlSource(null);
        return verifier;
    }

    /** A plain file, or `digest:<algorithm>:<file>` for a DigestDocument of that file's digest. */
    private static DSSDocument detachedContent(Path dir, String column) throws Exception {
        if (!column.startsWith("digest:")) {
            return new FileDocument(dir.resolve(column).toFile());
        }
        String[] parts = column.split(":", 3);
        DigestAlgorithm algorithm = DigestAlgorithm.forName(parts[1].replace("-", ""));
        FileDocument file = new FileDocument(dir.resolve(parts[2]).toFile());
        return new DigestDocument(algorithm, file.getDigestValue(algorithm));
    }

    private record Verdict(String outcome, String detail) {}

    private static Verdict verdict(File signature, DSSDocument content, File policy, CommonCertificateVerifier verifier) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(signature));
        validator.setCertificateVerifier(verifier);
        if (content != null) {
            validator.setDetachedContents(List.of(content));
        }
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
