package org.quanweng.zerosslacme4j.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.quanweng.zerosslacme4j.pojo.model.SubjectInfo;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import lombok.Data;
import lombok.AllArgsConstructor;

@Component
public class CryptoUtils {

    @Data
    @AllArgsConstructor
    public static class EncryptedKey {
        private byte[] encryptedData;
        private byte[] salt;
        private byte[] iv;
        private byte[] tag;
    }

    // 加密私钥
    public EncryptedKey encryptPrivateKey(byte[] keyBytes, byte[] password, int keySize)
        throws Exception {

        byte[] salt = generateRandomBytes(16);
        byte[] iv = generateRandomBytes(12);

        SecretKey secretKey = deriveAesKey(password, salt, keySize);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] encrypted = cipher.doFinal(keyBytes);
        byte[] tag = Arrays.copyOfRange(encrypted, encrypted.length - 16, encrypted.length);

        return new EncryptedKey(
            Arrays.copyOf(encrypted, encrypted.length - 16),
            salt,
            iv,
            tag
        );
    }

    // 生成CSR
    public static PKCS10CertificationRequest generateCsr(
        SubjectInfo subjectInfo,
        List<String> sans,
        KeyPair keyPair,
        String hashAlgo) throws Exception {

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        addIfNotNull(nameBuilder, BCStyle.CN, subjectInfo.getCn());
        addIfNotNull(nameBuilder, BCStyle.C, subjectInfo.getC());
        addIfNotNull(nameBuilder, BCStyle.ST, subjectInfo.getSt());
        addIfNotNull(nameBuilder, BCStyle.L, subjectInfo.getL());
        addIfNotNull(nameBuilder, BCStyle.O, subjectInfo.getO());
        addIfNotNull(nameBuilder, BCStyle.OU, subjectInfo.getOu());

        PKCS10CertificationRequestBuilder csrBuilder =
            new JcaPKCS10CertificationRequestBuilder(
                nameBuilder.build(),
                keyPair.getPublic()
            );

        if (sans != null && !sans.isEmpty()) {
            GeneralNames sanList = new GeneralNames(sans.stream()
                .map(name -> new GeneralName(GeneralName.dNSName, name))
                .toArray(GeneralName[]::new));
            csrBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                new Extensions(new Extension(
                    Extension.subjectAlternativeName,
                    false,
                    sanList.getEncoded()
                ))
            );
        }

        return csrBuilder.build(
            new JcaContentSignerBuilder(getSigAlgo(hashAlgo))
                .build(keyPair.getPrivate())
        );
    }

    private static void addIfNotNull(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null) builder.addRDN(oid, value);
    }

    // 生成随机字节
    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    // 派生AES密钥
    private SecretKey deriveAesKey(byte[] password, byte[] salt, int keySize) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            new String(password).toCharArray(),
            salt,
            100000, // 迭代次数
            keySize
        );
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // 获取签名算法
    private static String getSigAlgo(String hashAlgo) {
        return switch (hashAlgo.toUpperCase()) {
            case "SHA256" -> "SHA256withECDSA";
            case "SHA384" -> "SHA384withECDSA";
            case "SHA512" -> "SHA512withECDSA";
            default -> "SHA256withECDSA";
        };
    }
}
