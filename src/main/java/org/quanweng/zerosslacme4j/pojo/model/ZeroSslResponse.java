package org.quanweng.zerosslacme4j.pojo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ZeroSslResponse {
    private Boolean success;
    private String message;
    private Object data;
}