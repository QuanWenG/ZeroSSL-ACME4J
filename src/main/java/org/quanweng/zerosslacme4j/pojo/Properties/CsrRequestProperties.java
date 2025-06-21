package org.quanweng.zerosslacme4j.pojo.Properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "csr.req")
public class CsrRequestProperties {
    private List<String> subjectAltNames;
    private String curve;
    private String hashAlgorithm;
    private int aesKeySize;
    private String password;
}
