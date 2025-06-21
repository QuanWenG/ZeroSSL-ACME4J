package org.quanweng.zerosslacme4j.pojo.model;

import lombok.Data;

@Data
public class SubjectInfo {
    private String cn;           // Common Name (CN)
    private String c;            // Country (C)
    private String o;            // Organization (O)
    private String st;           // State/Province (ST)
    private String l;            // Locality (L)
    private String ou;           // Organizational Unit (OU)
    private String emailAddress; // Email Address
}
