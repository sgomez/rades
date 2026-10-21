///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 17+
//DEPS es.gob.afirma:afirma-crypto-validation:1.8.2
//DEPS es.gob.afirma:afirma-crypto-cades:1.8.2

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValiderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Verifies every signature in a manifest with AutoFirma and fails on any verdict the manifest does not expect. */
public class AutoFirma {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: AutoFirma <signature directory>...");
            System.exit(2);
        }
        List<String> mismatches = new ArrayList<>();
        int checked = 0;
        for (String arg : args) {
            Path dir = Path.of(arg);
            for (String line : Files.readAllLines(dir.resolve("manifest.tsv"))) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] entry = line.trim().split("\\s+");
                if (entry.length != 3) {
                    throw new IllegalArgumentException("manifest line is not `file indication level`: " + line);
                }
                Path signature = dir.resolve(entry[0]);
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
                SignValidity validity = SignValiderFactory.getSignValider(bytes).validate(bytes);
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
