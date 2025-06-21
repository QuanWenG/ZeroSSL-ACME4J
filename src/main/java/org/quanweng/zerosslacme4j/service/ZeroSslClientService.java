package org.quanweng.zerosslacme4j.service;

import lombok.extern.slf4j.Slf4j;
import org.quanweng.zerosslacme4j.pojo.Properties.SubjectInfoProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.quanweng.zerosslacme4j.pojo.model.*;

import java.util.Map;

@Slf4j
@Service
public class ZeroSslClientService {

    @Autowired
    private  CsrService csrService;
    @Autowired
    private SubjectInfoProperties subjectInfoProperties;


    @Value("${zerossl.api.base-url:https://api.zerossl.com}")
    private String baseUrl;

    @Value("${zerossl.api.access-key}")
    private String defaultAccessKey;

    private final RestTemplate restTemplate;

    public ZeroSslClientService() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * 1. 获取已有证书列表
     * GET https://api.zerossl.com/certificates?access_key={access_key}
     */
    public ZeroSslResponse getCertificateList(String accessKey) {
        try {
            String url = baseUrl + "/certificates?access_key=" + (accessKey != null ? accessKey : defaultAccessKey);

            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            return new ZeroSslResponse(true, "获取证书列表成功", response.getBody());
        } catch (Exception e) {
            return new ZeroSslResponse(false, "获取证书列表失败: " + e.getMessage(), null);
        }
    }

    /**
     * 2. 创建证书请求
     * POST https://api.zerossl.com/certificates
     */
    public ZeroSslResponse createCertificateRequest(CertificateCreateRequest request) {
        try {
            String url = baseUrl + "/certificates";
            
            // 修改：创建正确配置的CsrRequest对象
            CsrRequest csrRequest = new CsrRequest();
            csrRequest.setKeyType("RSA");
            csrRequest.setRsaKeySize(2048);
            
            String domainName = subjectInfoProperties.getCn();
            request.setCertificateDomains(domainName);
            
            // 生成CSR并添加详细调试
            String csrPem = csrService.generateCsrAndKey(csrRequest).getCsrPem();
            request.setCertificateCsr(csrPem);
            
            // 添加详细的CSR和域名调试信息
            log.info("=== 证书创建请求详细调试 ===");
            log.info("域名: [{}]", domainName);
            log.info("域名长度: {} 字符", domainName != null ? domainName.length() : 0);
            
            // 修正：正确的特殊字符检测正则表达式
            boolean hasSpecialChars = domainName != null && !domainName.matches("^[a-zA-Z0-9.-]+$");
            log.info("域名是否包含特殊字符: {}", hasSpecialChars);
            
            log.info("CSR长度: {} 字符", csrPem != null ? csrPem.length() : 0);
            log.info("CSR开始: {}", csrPem != null && csrPem.length() > 50 ? csrPem.substring(0, 50) : csrPem);
            log.info("CSR结束: {}", csrPem != null && csrPem.length() > 50 ? csrPem.substring(csrPem.length() - 50) : csrPem);
            
            // 新增：检查CSR中的域名信息
            if (csrPem != null && csrPem.contains("BEGIN CERTIFICATE REQUEST")) {
                try {
                    // 解码CSR以检查其中的域名信息
                    byte[] csrBytes = java.util.Base64.getDecoder().decode(
                        csrPem.replaceAll("-----BEGIN CERTIFICATE REQUEST-----", "")
                              .replaceAll("-----END CERTIFICATE REQUEST-----", "")
                              .replaceAll("\\s", "")
                    );
                    
                    // 这里可以添加更详细的CSR解析逻辑
                    log.info("CSR解码成功，字节长度: {}", csrBytes.length);
                } catch (Exception e) {
                    log.warn("CSR解码失败: {}", e.getMessage());
                }
            }
            
            // 验证CSR格式
            if (csrPem == null || csrPem.trim().isEmpty()) {
                log.error("CSR为空或null");
                return new ZeroSslResponse(false, "CSR生成失败", null);
            }
            
            if (!csrPem.contains("-----BEGIN CERTIFICATE REQUEST-----") || 
                !csrPem.contains("-----END CERTIFICATE REQUEST-----")) {
                log.error("CSR格式不正确，缺少标准的开始或结束标记");
                return new ZeroSslResponse(false, "CSR格式不正确", null);
            }
            
            // 验证域名格式
            if (domainName == null || domainName.trim().isEmpty()) {
                log.error("域名为空");
                return new ZeroSslResponse(false, "域名不能为空", null);
            }
            
            // 检查域名是否为IP地址
            // 注释掉或删除这段代码
            // if (domainName.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            //     log.warn("检测到IP地址作为域名: {}，ZeroSSL不支持IP证书", domainName);
            //     return new ZeroSslResponse(false, "ZeroSSL不支持IP地址证书", null);
            // }
            
            // 检查是否包含无效字符
            if (hasSpecialChars) {
                log.error("域名包含无效字符: {}", domainName);
                return new ZeroSslResponse(false, "域名包含无效字符", null);
            }
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("access_key", request.getAccessKey() != null ? request.getAccessKey() : defaultAccessKey);
            body.add("certificate_domains", request.getCertificateDomains());
            body.add("certificate_validity_days", request.getCertificateValidityDays().toString());
            body.add("strict_domains", request.getStrictDomains().toString());
            body.add("certificate_csr", request.getCertificateCsr());
            
            // 添加调试信息
            log.info("=== ZeroSSL API Request Debug ===");
            log.info("URL: {}", url);
            log.info("Content-Type: {}", headers.getContentType());
            log.info("Certificate Domains: {}", body.getFirst("certificate_domains"));
            log.info("Certificate Validity Days: {}", body.getFirst("certificate_validity_days"));
            log.info("Strict Domains: {}", body.getFirst("strict_domains"));
            
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);
            
            return new ZeroSslResponse(true, "创建证书请求成功", response.getBody());
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("HTTP Client Error: Status={}, Headers={}, Body={}", 
                e.getStatusCode(), e.getResponseHeaders(), e.getResponseBodyAsString());
            
            // 增强错误分析
            if (e.getStatusCode().value() == 401) {
                if (e.getResponseBodyAsString().isEmpty()) {
                    log.warn("401错误且响应体为空，可能原因：");
                    log.warn("1. 证书配额已满（免费账户通常限制3个证书）");
                    log.warn("2. CSR中的域名与请求域名不匹配");
                    log.warn("3. 域名验证失败或域名不可访问");
                    log.warn("4. API密钥权限不足");
                } else {
                    log.warn("401错误详细信息: {}", e.getResponseBodyAsString());
                }
            }
            
            return new ZeroSslResponse(false, 
                "创建证书请求失败: " + e.getStatusCode() + " - " + e.getResponseBodyAsString(), null);
        } catch (Exception e) {
            log.error("General Error: ", e);
            return new ZeroSslResponse(false, "创建证书请求失败: " + e.getMessage(), null);
        }
    }

    /**
     * 3. 验证证书请求
     * POST https://api.zerossl.com/certificates/{id}/challenges
     */
    public ZeroSslResponse validateCertificateRequest(String certificateId, CertificateValidationRequest request) {
        try {
            String url = baseUrl + "/certificates/" + certificateId + "/challenges";
    
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");
            
            // 修正：只添加CertificateValidationRequest实际拥有的字段
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("access_key", request.getAccessKey() != null ? request.getAccessKey() : defaultAccessKey);
            body.add("validation_method", request.getValidationMethod());
            if (request.getEmail() != null && !request.getEmail().isEmpty()) {
                body.add("email", request.getEmail());
            }
            
            // 移除这些不存在的方法调用：
            // body.add("certificate_domains", request.getCertificateDomains());
            // body.add("certificate_validity_days", request.getCertificateValidityDays().toString());
            // body.add("strict_domains", request.getStrictDomains().toString());
            // body.add("certificate_csr", request.getCertificateCsr());
            
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);
            
            return new ZeroSslResponse(true, "验证证书请求成功", response.getBody());
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            log.error("HTTP Client Error: Status={}, Headers={}, Body={}", 
                e.getStatusCode(), e.getResponseHeaders(), e.getResponseBodyAsString());
            
            // 增强错误处理：尝试解析JSON错误响应
            String responseBody = e.getResponseBodyAsString();
            if (responseBody.isEmpty()) {
                log.warn("响应体为空，可能是RestTemplate解析问题");
                // 尝试获取原始响应
                try {
                    log.error("Raw response headers: {}", e.getResponseHeaders());
                    log.error("Status code: {}", e.getStatusCode());
                } catch (Exception ex) {
                    log.error("无法获取详细错误信息", ex);
                }
            } else {
                log.info("收到错误响应: {}", responseBody);
                // 尝试解析特定错误
                if (responseBody.contains("certificate_limit_reached")) {
                    return new ZeroSslResponse(false, 
                        "证书创建失败：已达到账户证书创建限制。请删除现有证书或升级账户。", null);
                }
            }
            
            return new ZeroSslResponse(false, 
                "创建证书请求失败: " + e.getStatusCode() + " - " + responseBody, null);
        } catch (org.springframework.web.client.HttpServerErrorException e) {
            log.error("HTTP Server Error: Status={}, Body={}", 
                e.getStatusCode(), e.getResponseBodyAsString());
            return new ZeroSslResponse(false, 
                "服务器错误: " + e.getStatusCode() + " - " + e.getResponseBodyAsString(), null);
        } catch (Exception e) {
            log.error("General Error: ", e);
            return new ZeroSslResponse(false, "创建证书请求失败: " + e.getMessage(), null);
        }
    }

    /**
     * 4. 验证证书通过状态
     * GET https://api.zerossl.com/certificates/{id}/status
     */
    public ZeroSslResponse getCertificateStatus(String certificateId, String accessKey) {
        try {
            String url = baseUrl + "/certificates/" + certificateId + "/status?access_key=" +
                        (accessKey != null ? accessKey : defaultAccessKey);

            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            return new ZeroSslResponse(true, "获取证书状态成功", response.getBody());
        } catch (Exception e) {
            return new ZeroSslResponse(false, "获取证书状态失败: " + e.getMessage(), null);
        }
    }

    /**
     * 5. 请求证书信息
     * GET https://api.zerossl.com/certificates/{id}
     */
    public ZeroSslResponse getCertificateInfo(String certificateId, String accessKey) {
        try {
            String url = baseUrl + "/certificates/" + certificateId + "?access_key=" +
                        (accessKey != null ? accessKey : defaultAccessKey);

            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            return new ZeroSslResponse(true, "获取证书信息成功", response.getBody());
        } catch (Exception e) {
            return new ZeroSslResponse(false, "获取证书信息失败: " + e.getMessage(), null);
        }
    }

    /**
     * 6. 获取已有证书（下载）
     * GET https://api.zerossl.com/certificates/{id}/download/return
     */
    public ZeroSslResponse downloadCertificate(String certificateId, String accessKey, Boolean includeCrossSigned) {
        try {
            String url = baseUrl + "/certificates/" + certificateId + "/download/return?access_key=" +
                        (accessKey != null ? accessKey : defaultAccessKey);
            if (includeCrossSigned != null && includeCrossSigned) {
                url += "&include_cross_signed=1";
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED); // 改为表单格式
            headers.set("User-Agent", "ZeroSSL-ACME4J/1.0");
            headers.set("Accept", "application/json");
            // 移除其他可能干扰的头部
            headers.set("Accept", "*/*");
            headers.set("Accept-Language", "zh-HK");

            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            return new ZeroSslResponse(true, "下载证书成功", response.getBody());
        } catch (Exception e) {
            return new ZeroSslResponse(false, "下载证书失败: " + e.getMessage(), null);
        }
    }


public ResponseEntity<String> createCertificateRequestV2(CertificateCreateRequest request) {
    try {
        // 添加详细的调试日志
        log.info("=== 证书创建请求调试信息 ===");
        log.info("域名: {}", request.getCertificateDomains());
        log.info("有效期: {} 天", request.getCertificateValidityDays());
        log.info("严格域名: {}", request.getStrictDomains());
        
        // 检查CSR
        String csr = request.getCertificateCsr();
        log.info("CSR长度: {} 字符", csr != null ? csr.length() : 0);
        log.info("CSR前100字符: {}", csr != null && csr.length() > 100 ? csr.substring(0, 100) : csr);
        
        // 验证CSR格式
        if (csr == null || csr.trim().isEmpty()) {
            log.error("CSR为空或null");
            return ResponseEntity.badRequest().body("{\"error\":\"CSR不能为空\"}");
        }
        
        if (!csr.contains("-----BEGIN CERTIFICATE REQUEST-----") || 
            !csr.contains("-----END CERTIFICATE REQUEST-----")) {
            log.error("CSR格式不正确，缺少标准的开始或结束标记");
            return ResponseEntity.badRequest().body("{\"error\":\"CSR格式不正确\"}");
        }

        String url = "https://api.zerossl.com/certificates";
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.set("User-Agent", "ZeroSSL-Java-Client/1.0");
        headers.set("Accept", "application/json");
        headers.set("Accept-Language", "en-US,en;q=0.9");
        
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("access_key", request.getAccessKey() != null ? request.getAccessKey() : defaultAccessKey);
        body.add("certificate_domains", request.getCertificateDomains());
        body.add("certificate_validity_days", request.getCertificateValidityDays());
        body.add("strict_domains", request.getStrictDomains());
        body.add("certificate_csr", csr);
        
        // 记录请求详情
        log.info("请求URL: {}", url);
        log.info("请求头: {}", headers);
        log.info("请求体参数数量: {}", body.size());
        
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
        return response;
    } catch (Exception e) {
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body("{\"success\":false,\"message\":\"创建证书请求失败: " + e.getMessage() + "\"}");
    }
    }
}
