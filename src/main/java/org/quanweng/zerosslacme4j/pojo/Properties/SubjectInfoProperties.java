package org.quanweng.zerosslacme4j.pojo.Properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "csr.sub")
public class SubjectInfoProperties {
    private String cn;           // Common Name (CN)
    private String c;            // Country (C)
    private String o;            // Organization (O)
    private String st;           // State/Province (ST)
    private String l;            // Locality (L)
    private String ou;           // Organizational Unit (OU)
    private String emailAddress; // Email Address
}
