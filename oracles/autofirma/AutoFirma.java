///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 17+
//DEPS es.gob.afirma:afirma-crypto-validation:1.8.2
//DEPS es.gob.afirma:afirma-crypto-cades:1.8.2

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValiderFactory;
import es.gob.afirma.signvalidation.ValidateBinarySignature;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Verifies every signature in a manifest with AutoFirma and fails on any verdict the manifest does not expect. */
public class AutoFirma {
    private static final String SKIP_PREFIX = "#autofirma-skip ";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: AutoFirma <signature directory>...");
            System.exit(2);
        }
        List<String> mismatches = new ArrayList<>();
        int checked = 0;
        for (String arg : args) {
            Path dir = Path.of(arg);
            List<String> lines = Files.readAllLines(dir.resolve("manifest.tsv"));
            Set<String> unjudged = new HashSet<>();
            for (String line : lines) {
                if (line.startsWith(SKIP_PREFIX)) {
                    unjudged.add(line.substring(SKIP_PREFIX.length()).trim().split("\\s+")[0]);
                }
            }
            for (String line : lines) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] entry = line.trim().split("\\s+");
                if (entry.length != 3 && entry.length != 4) {
                    throw new IllegalArgumentException("manifest line is not `file indication level [content]`: " + line);
                }
                Path signature = dir.resolve(entry[0]);
                if (unjudged.contains(entry[0])) {
                    System.out.println("skipped  " + signature + ": the manifest records AutoFirma cannot judge it");
                    continue;
                }
                SignValidity.SIGN_DETAIL_TYPE expected = switch (entry[1]) {
                    case "TOTAL_PASSED" -> SignValidity.SIGN_DETAIL_TYPE.OK;
                    case "TOTAL_FAILED" -> SignValidity.SIGN_DETAIL_TYPE.KO;
                    default -> null;
                };
                if (expected == null) {
                    System.out.println("skipped  " + signature + ": AutoFirma has no verdict for " + entry[1]);
                    continue;
                }
                byte[] bytes = Files.readAllBytes(signature);
                SignValidity validity = entry.length == 4
                        ? ValidateBinarySignature.validate(bytes, Files.readAllBytes(dir.resolve(entry[3].replaceFirst("^digest:[^:]*:", ""))))
                        : SignValiderFactory.getSignValider(bytes).validate(bytes);
                checked++;
                if (validity.getValidity() == expected) {
                    System.out.println("ok       " + signature + ": " + validity.getValidity());
                } else {
                    System.out.println("MISMATCH " + signature + ": expected " + expected + ", got "
                            + validity.getValidity() + " (" + validity.getError() + ")");
                    mismatches.add(signature.toString());
                }
            }
        }
        if (!mismatches.isEmpty()) {
            System.err.println("AutoFirma disagrees with the manifest on: " + String.join(", ", mismatches));
            System.exit(1);
        }
        System.out.println("AutoFirma agrees with the manifest on " + checked + " signatures");
    }
}
