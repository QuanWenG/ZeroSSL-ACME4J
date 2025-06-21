package org.quanweng.zerosslacme4j.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class KeyUtils {

    // 生成EC密钥
    public static KeyPair generateECKey(String curveName) throws Exception {
        ECGenParameterSpec spec = new ECGenParameterSpec(
            curveMapper(curveName)
        );
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(spec);
        return gen.generateKeyPair();
    }

    // OpenSSL传统格式PEM
    public static String convertToOpenSSLPEM(PrivateKey privateKey) throws Exception {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        ASN1Encodable asn1 = pki.parsePrivateKey();
        return "-----BEGIN EC PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(asn1.toASN1Primitive().getEncoded()) +
            "\n-----END EC PRIVATE KEY-----";
    }

    // 编码CSR为PEM格式
    public static byte[] encodeToPem(PKCS10CertificationRequest csr) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return stringWriter.toString().getBytes();
    }

    private static String curveMapper(String curve) {
        return switch (curve) {
            case "secp256r1" -> "secp256r1";
            case "secp384r1" -> "secp384r1";
            default -> "secp521r1";
        };
    }
}
