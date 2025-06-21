package org.quanweng.zerosslacme4j.pojo.model;

import lombok.Data;

@Data
public class CertificateValidationRequest {
    private String accessKey;
    private String validationMethod = "HTTP_CSR_HASH";  // 验证方法
    private String email;                               // 可选的邮箱地址
}