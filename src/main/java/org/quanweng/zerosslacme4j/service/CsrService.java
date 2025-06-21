package org.quanweng.zerosslacme4j.service;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.quanweng.zerosslacme4j.pojo.Properties.CsrRequestProperties;
import org.quanweng.zerosslacme4j.pojo.Properties.SubjectInfoProperties;
import org.quanweng.zerosslacme4j.pojo.model.CsrRequest;
import org.quanweng.zerosslacme4j.pojo.model.KeyBundle;
import org.quanweng.zerosslacme4j.pojo.model.SubjectInfo;
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
    @Autowired
    private SubjectInfoProperties subjectInfoProperties;
    @Autowired
    private CsrRequestProperties csrRequestProperties;

    public KeyBundle generateCsrAndKey(CsrRequest request) throws Exception {
        //配置类注入
        if(request.getSubjectInfo() == null) {
            SubjectInfo subjectInfo = new SubjectInfo();
            subjectInfo.setCn(subjectInfoProperties.getCn());
            subjectInfo.setC(subjectInfoProperties.getC());
            subjectInfo.setSt(subjectInfoProperties.getSt());
            subjectInfo.setL(subjectInfoProperties.getL());
            subjectInfo.setO(subjectInfoProperties.getO());
            subjectInfo.setOu(subjectInfoProperties.getOu());
            subjectInfo.setEmailAddress(subjectInfoProperties.getEmailAddress());
            request.setSubjectInfo(subjectInfo);
        }
        if(request.getSubjectAltNames() == null) {
            request.setSubjectAltNames(csrRequestProperties.getSubjectAltNames());
        }
        if(request.getPassword() == null) {
            request.setPassword(csrRequestProperties.getPassword());
        }
        
        // 修改：根据keyType生成对应的密钥对
        KeyPair keyPair;
        if ("RSA".equals(request.getKeyType())) {
            keyPair = KeyUtils.generateRSAKey(request.getRsaKeySize());
        } else {
            keyPair = KeyUtils.generateECKey(request.getCurve());
        }
    
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
