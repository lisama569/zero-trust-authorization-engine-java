package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 端到端 REST 接口测试：策略治理、授权评估、可区分失败码、异常不穿透。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "zt.audit.file=build/audit/web-api-test.log")
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.APPLICATION_JSON);
        return h;
    }

    private static final String ALLOW_POLICY = """
            {
              "schemaVersion": 1,
              "policyId": "root",
              "version": "api-v-allow",
              "rules": [
                {"id": "r-admin", "effect": "ALLOW",
                 "conditions": [
                   {"source": "SUBJECT", "attribute": "role", "op": "eq",
                    "expected": "admin"},
                   {"source": "RESOURCE", "attribute": "sensitivity", "op": "le",
                    "expected": "3"},
                   {"source": "ENVIRONMENT", "attribute": "network", "op": "eq",
                    "expected": "corp"}]}
              ]
            }
            """;

    private static final String EVAL_BODY = """
            {
              "subject": {"id": "u1", "attributes": {"role": "admin"}},
              "resource": {"id": "d1", "attributes": {"sensitivity": "2"}},
              "action": "read",
              "environment": {"attributes": {"network": "corp"}}
            }
            """;

    @Test
    void fullFlowLoadPublishEvaluateRollback() {
        ResponseEntity<String> load = restTemplate.postForEntity(
                url("/api/policies/load"),
                new HttpEntity<>(ALLOW_POLICY, jsonHeaders()), String.class);
        log.info("[HTTP load] status={}, body={}", load.getStatusCode(), load.getBody());
        assertEquals(HttpStatus.OK, load.getStatusCode());

        ResponseEntity<String> publish = restTemplate.postForEntity(
                url("/api/policies/api-v-allow/publish"), null, String.class);
        log.info("[HTTP publish] status={}", publish.getStatusCode());
        assertEquals(HttpStatus.OK, publish.getStatusCode());

        ResponseEntity<String> allowed = restTemplate.exchange(
                url("/api/authz/evaluate"),
                org.springframework.http.HttpMethod.POST,
                new HttpEntity<>(EVAL_BODY, jsonHeaders()), String.class);
        log.info("[HTTP evaluate] status={}, body={}",
                allowed.getStatusCode(), allowed.getBody());
        assertEquals(HttpStatus.OK, allowed.getStatusCode());
        assertTrue(allowed.getBody().contains("PERMIT"));
        assertTrue(allowed.getBody().contains("api-v-allow"));

        ResponseEntity<String> rollback = restTemplate.postForEntity(
                url("/api/policies/v0-bootstrap/rollback"), null, String.class);
        log.info("[HTTP rollback] status={}", rollback.getStatusCode());
        assertEquals(HttpStatus.OK, rollback.getStatusCode());
    }

    @Test
    void unknownFieldInPolicyReturns422WithDistinctCode() {
        String bad = ALLOW_POLICY.replace("\"rules\":", "\"mystery\": 1, \"rules\":");
        ResponseEntity<String> resp = restTemplate.postForEntity(
                url("/api/policies/load"),
                new HttpEntity<>(bad, jsonHeaders()), String.class);
        log.info("[HTTP 未知策略字段] status={}, body={}",
                resp.getStatusCode(), resp.getBody());
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resp.getStatusCode());
        assertTrue(resp.getBody().contains("UNKNOWN_FIELD"));
    }

    @Test
    void unknownFieldInAccessRequestReturns400() {
        String bad = EVAL_BODY.replace("\"action\":", "\"hackerField\": 7, \"action\":");
        ResponseEntity<String> resp = restTemplate.exchange(
                url("/api/authz/evaluate"),
                org.springframework.http.HttpMethod.POST,
                new HttpEntity<>(bad, jsonHeaders()), String.class);
        log.info("[HTTP 未知请求字段] status={}, body={}",
                resp.getStatusCode(), resp.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertTrue(resp.getBody().contains("UNKNOWN_FIELD"));
    }

    @Test
    void rollbackMissingTargetReturnsDistinctCode() {
        ResponseEntity<String> resp = restTemplate.postForEntity(
                url("/api/policies/no-such-version/rollback"), null, String.class);
        log.info("[HTTP 回滚缺失] status={}, body={}",
                resp.getStatusCode(), resp.getBody());
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resp.getStatusCode());
        assertTrue(resp.getBody().contains("ROLLBACK_TARGET_NOT_FOUND"));
    }

    @Test
    void conflictingPolicyReturns422ConflictCode() {
        String conflict = """
                {
                  "schemaVersion": 1, "policyId": "root", "version": "api-conflict",
                  "rules": [
                    {"id": "a", "effect": "ALLOW", "conditions": [
                      {"source": "SUBJECT", "attribute": "role", "op": "eq",
                       "expected": "admin"}]},
                    {"id": "b", "effect": "DENY", "conditions": [
                      {"source": "SUBJECT", "attribute": "role", "op": "eq",
                       "expected": "admin"}]}
                  ]
                }
                """;
        ResponseEntity<String> resp = restTemplate.postForEntity(
                url("/api/policies/load"),
                new HttpEntity<>(conflict, jsonHeaders()), String.class);
        log.info("[HTTP 冲突策略] status={}, body={}",
                resp.getStatusCode(), resp.getBody());
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, resp.getStatusCode());
        assertTrue(resp.getBody().contains("CONFLICTING_RULES"));
    }

    @Test
    void statusAndAuditEndpointsWork() {
        ResponseEntity<String> status = restTemplate.getForEntity(
                url("/api/policies/status"), String.class);
        log.info("[HTTP status] body={}", status.getBody());
        assertEquals(HttpStatus.OK, status.getStatusCode());
        assertNotNull(status.getBody());
        assertTrue(status.getBody().contains("v0-bootstrap"));

        ResponseEntity<String> verify = restTemplate.getForEntity(
                url("/api/audit/verify"), String.class);
        log.info("[HTTP audit verify] body={}", verify.getBody());
        assertEquals(HttpStatus.OK, verify.getStatusCode());
        assertTrue(verify.getBody().contains("\"intact\":true"));
    }
}
