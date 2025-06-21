package org.quanweng.zerosslacme4j.pojo.model;

import lombok.Data;

import java.util.List;

@Data
public class CsrRequest {
    private SubjectInfo subjectInfo;
    private List<String> subjectAltNames;
    private String curve = "secp256r1";
    private String hashAlgorithm = "SHA256";
    private int aesKeySize = 256;
    private String password;
    private String keyType = "RSA"; // RSA 或 EC
    private int rsaKeySize = 2048; // RSA密钥长度，2048或4096
}
