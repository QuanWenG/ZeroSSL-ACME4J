package org.quanweng.zerosslacme4j.pojo.model;

import lombok.Data;

@Data
public class CertificateCreateRequest {
    private String accessKey;
    private String certificateDomains;        // 域名
    private Integer certificateValidityDays = 90;
    private Integer strictDomains = 1;
    private String certificateCsr;            // Base64编码的CSR
}
