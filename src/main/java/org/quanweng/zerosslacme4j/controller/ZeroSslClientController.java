package org.quanweng.zerosslacme4j.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.quanweng.zerosslacme4j.service.ZeroSslClientService;
import org.quanweng.zerosslacme4j.pojo.model.*;

@RestController
@RequestMapping("/api/zerossl-client")
public class ZeroSslClientController {

    @Autowired
    private ZeroSslClientService zeroSslClientService;

    /**
     * 获取证书列表
     */
    @GetMapping("/certificates")
    public ResponseEntity<ZeroSslResponse> getCertificates(
            @RequestParam(required = false) String accessKey) {
        ZeroSslResponse response = zeroSslClientService.getCertificateList(accessKey);
        return ResponseEntity.ok(response);
    }

    /**
     * 创建证书请求
     */
    @PostMapping("/certificates")
    public ResponseEntity<ZeroSslResponse> createCertificate(
            @RequestBody CertificateCreateRequest request) {
        ZeroSslResponse response = zeroSslClientService.createCertificateRequest(request);
        return ResponseEntity.ok(response);
    }

    /**
     * 验证证书请求
     */
    @PostMapping("/certificates/{certificateId}/validate")
    public ResponseEntity<ZeroSslResponse> validateCertificate(
            @PathVariable String certificateId,
            @ModelAttribute CertificateValidationRequest request) {
        ZeroSslResponse response = zeroSslClientService.validateCertificateRequest(certificateId, request);
        return ResponseEntity.ok(response);
    }

    /**
     * 获取证书状态
     */
    @GetMapping("/certificates/{certificateId}/status")
    public ResponseEntity<ZeroSslResponse> getCertificateStatus(
            @PathVariable String certificateId,
            @RequestParam(required = false) String accessKey) {
        ZeroSslResponse response = zeroSslClientService.getCertificateStatus(certificateId, accessKey);
        return ResponseEntity.ok(response);
    }

    /**
     * 获取证书信息
     */
    @GetMapping("/certificates/{certificateId}")
    public ResponseEntity<ZeroSslResponse> getCertificateInfo(
            @PathVariable String certificateId,
            @RequestParam(required = false) String accessKey) {
        ZeroSslResponse response = zeroSslClientService.getCertificateInfo(certificateId, accessKey);
        return ResponseEntity.ok(response);
    }

    /**
     * 下载证书
     */
    @GetMapping("/certificates/{certificateId}/download")
    public ResponseEntity<ZeroSslResponse> downloadCertificate(
            @PathVariable String certificateId,
            @RequestParam(required = false) String accessKey,
            @RequestParam(defaultValue = "true") Boolean includeCrossSigned) {
        ZeroSslResponse response = zeroSslClientService.downloadCertificate(certificateId, accessKey, includeCrossSigned);
        return ResponseEntity.ok(response);
    }
}
