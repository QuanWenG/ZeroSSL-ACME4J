package org.quanweng.zerosslacme4j.controller;

import org.quanweng.zerosslacme4j.pojo.model.CsrRequest;
import org.quanweng.zerosslacme4j.pojo.model.KeyBundle;
import org.quanweng.zerosslacme4j.service.CsrService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/csr")
public class CsrController {

    @Autowired
    private CsrService csrService;

    @PostMapping("/generate")
    public ResponseEntity<KeyBundle> generateCsr(@RequestBody CsrRequest request) {
        try {
            return ResponseEntity.ok(csrService.generateCsrAndKey(request));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
}
