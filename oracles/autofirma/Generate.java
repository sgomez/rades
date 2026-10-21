///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 17+
//DEPS es.gob.afirma:afirma-crypto-validation:1.8.2
//DEPS es.gob.afirma:afirma-crypto-cades:1.8.2
//DEPS es.gob.afirma:afirma-crypto-cades-multi:1.8.2

import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.signers.ExtraParamsProcessor;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValiderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Properties;

/** Makes AutoFirma's CAdES fixtures with the test PKI; run by hand, the output is committed. */
public class Generate {
    private static final char[] PASSWORD = "rades".toCharArray();

    record Signer(String name, String algorithm, PrivateKey key, Certificate[] chain) {}

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: Generate <test PKI directory> <output directory>");
            System.exit(2);
        }
        Path pki = Path.of(args[0]);
        Path out = Path.of(args[1]);
        byte[] content = Files.readAllBytes(pki.resolve("content.txt"));
        Signer rsa = load(pki, "signer-rsa", "SHA256withRSA");
        Signer ecdsa = load(pki, "signer-ecdsa", "SHA256withECDSA");
        AOCAdESSigner cades = new AOCAdESSigner();

        for (Signer signer : new Signer[] {rsa, ecdsa}) {
            String suffix = signer.name().substring("signer-".length());
            write(out, "attached-" + suffix + ".p7s", sign(cades, content, signer, "implicit"), null);
            write(out, "detached-" + suffix + ".p7s", sign(cades, content, signer, "explicit"), content);
            Properties age = params("implicit");
            age.setProperty("expPolicy", "FirmaAGE");
            write(out, "attached-" + suffix + "-age.p7s", cades.sign(content, signer.algorithm(), signer.key(), signer.chain(), ExtraParamsProcessor.expandProperties(age, content, "CAdES")), null);
        }

        byte[] base = sign(cades, content, ecdsa, "implicit");
        byte[] cosigned = cades.cosign(base, rsa.algorithm(), rsa.key(), rsa.chain(), params("implicit"));
        write(out, "cosign-ecdsa-rsa.p7s", cosigned, null);

        byte[] countersigned = cades.countersign(
                base, rsa.algorithm(), CounterSignTarget.TREE, null, rsa.key(), rsa.chain(), params("implicit"));
        write(out, "countersign-ecdsa-by-rsa.p7s", countersigned, null);
    }

    private static Signer load(Path pki, String name, String algorithm) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pki.resolve(name + ".p12"))) {
            store.load(in, PASSWORD);
        }
        return new Signer(
                name, algorithm, (PrivateKey) store.getKey(name, PASSWORD), store.getCertificateChain(name));
    }

    private static Properties params(String mode) {
        Properties params = new Properties();
        params.setProperty("mode", mode);
        return params;
    }

    private static byte[] sign(AOCAdESSigner cades, byte[] content, Signer signer, String mode) throws Exception {
        return cades.sign(content, signer.algorithm(), signer.key(), signer.chain(), params(mode));
    }

    private static void write(Path out, String file, byte[] signature, byte[] detachedContent) throws Exception {
        SignValidity validity = detachedContent == null
                ? SignValiderFactory.getSignValider(signature).validate(signature)
                : es.gob.afirma.signvalidation.ValidateBinarySignature.validate(signature, detachedContent);
        if (validity.getValidity() != SignValidity.SIGN_DETAIL_TYPE.OK) {
            throw new IllegalStateException(file + " does not verify: " + validity.getValidity() + " " + validity.getError() + " " + validity.getErrorException());
        }
        Files.createDirectories(out);
        Files.write(out.resolve(file), signature);
        System.out.println("wrote " + out.resolve(file));
    }
}
