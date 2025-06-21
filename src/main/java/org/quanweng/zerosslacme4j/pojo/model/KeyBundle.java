package org.quanweng.zerosslacme4j.pojo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.quanweng.zerosslacme4j.utils.CryptoUtils;

@Data
@AllArgsConstructor
public class KeyBundle {
    private CryptoUtils.EncryptedKey encryptedPrivateKey;
    private String opensslStyleKey;
    private String csrPem;
}
