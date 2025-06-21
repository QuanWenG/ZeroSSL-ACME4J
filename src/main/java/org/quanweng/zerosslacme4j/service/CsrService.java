package org.quanweng.zerosslacme4j.service;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.quanweng.zerosslacme4j.pojo.model.CsrRequest;
import org.quanweng.zerosslacme4j.pojo.model.KeyBundle;
import org.quanweng.zerosslacme4j.utils.CryptoUtils;
import org.quanweng.zerosslacme4j.utils.KeyUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

@Service
public class CsrService {

    @Autowired
    private CryptoUtils cryptoUtils;

    public KeyBundle generateCsrAndKey(CsrRequest request) throws Exception {
        // 生成密钥对
        KeyPair keyPair = KeyUtils.generateECKey(request.getCurve());

        // 生成CSR
        PKCS10CertificationRequest csr = CryptoUtils.generateCsr(
            request.getSubjectInfo(),
            request.getSubjectAltNames(),
            keyPair,
            request.getHashAlgorithm()
        );

        // 加密私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        CryptoUtils.EncryptedKey encryptedKey = cryptoUtils.encryptPrivateKey(
            privateKeyBytes,
            request.getPassword().getBytes(StandardCharsets.UTF_8),
            request.getAesKeySize()
        );

        return new KeyBundle(
            encryptedKey,
            KeyUtils.convertToOpenSSLPEM(keyPair.getPrivate()),
            new String(KeyUtils.encodeToPem(csr), StandardCharsets.UTF_8)
        );
    }
}
