package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP 端到端测试：
 * 评估五类结论中的典型路径、治理失败原因可区分、审计接口可用。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WebApiTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @LocalServerPort
    private int port;
    @Autowired
    private TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private record ApiResponse(int status, JsonNode body) {
    }

    private ApiResponse post(String path, String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> resp = rest.postForEntity(url(path),
                new HttpEntity<>(body, headers), String.class);
        log.info("POST {} -> status={} body={}", path, resp.getStatusCode(), resp.getBody());
        try {
            return new ApiResponse(resp.getStatusCode().value(), mapper.readTree(resp.getBody()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private JsonNode get(String path) {
        ResponseEntity<String> resp = rest.getForEntity(url(path), String.class);
        log.info("GET {} -> status={} body={}", path, resp.getStatusCode(), resp.getBody());
        try {
            return mapper.readTree(resp.getBody());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String evalBody(String subject, String action, String resource,
                            Map<String, String> env) {
        try {
            return mapper.writeValueAsString(Map.of(
                    "subjectId", subject, "action", action, "resourceId", resource,
                    "environment", env == null ? Map.of() : env));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("HTTP 评估：允许 / 显式拒绝 / 上下文缺失 / 默认拒绝可区分")
    void evaluationDecisionsOverHttp() {
        ApiResponse allow = post("/api/authz/evaluate",
                evalBody("alice", "read", "doc-internal", Map.of()));
        assertEquals("ALLOW", allow.body().get("decision").asText());

        ApiResponse deny = post("/api/authz/evaluate",
                evalBody("carol", "read", "doc-secret", Map.of()));
        assertEquals("DENY", deny.body().get("decision").asText());
        assertEquals("r-deny-contractor-secret", deny.body().get("matchedRuleId").asText());

        ApiResponse missing = post("/api/authz/evaluate",
                evalBody("bob", "read", "doc-secret", Map.of()));
        assertEquals("CONTEXT_MISSING", missing.body().get("decision").asText());

        ApiResponse noMatch = post("/api/authz/evaluate",
                evalBody("ghost", "read", "doc-public", Map.of()));
        assertEquals("POLICY_NOT_MATCHED", noMatch.body().get("decision").asText());
        assertNotNull(noMatch.body().get("auditId").asText());
    }

    @Test
    @DisplayName("发布未知字段策略：422 + failureReason=UNKNOWN_FIELD")
    void unknownFieldOverHttp() {
        String policyWithUnknownField = "{"
                + "\"policyVersion\":\"9.9.1\",\"schemaVersion\":\"1.0\","
                + "\"hacker\":true,"
                + "\"rules\":[{\"id\":\"x\",\"effect\":\"ALLOW\","
                + "\"roles\":[\"engineer\"],\"resourceType\":\"document\","
                + "\"maxSensitivity\":1,\"actions\":[\"read\"],"
                + "\"requiredEnvironment\":{}}]}";
        String body;
        try {
            body = mapper.writeValueAsString(Map.of("note", "bad",
                    "policyJson", policyWithUnknownField));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        ApiResponse node = post("/api/policies/publish", body);
        assertEquals("422", String.valueOf(node.status()));
        assertEquals("UNKNOWN_FIELD", node.body().get("failureReason").asText());
    }

    @Test
    @DisplayName("回滚不存在版本：422 + VERSION_NOT_FOUND，且不泄露堆栈")
    void rollbackUnknownOverHttp() {
        ApiResponse node = post("/api/policies/rollback",
                "{\"targetVersion\":\"no-such-version\"}");
        assertEquals("422", String.valueOf(node.status()));
        assertEquals("VERSION_NOT_FOUND", node.body().get("failureReason").asText());
        assertFalse(node.body().get("message").asText().contains("Exception"));
    }

    @Test
    @DisplayName("审计记录与校验接口可访问且链完整")
    void auditEndpoints() {
        ApiResponse ignored = post("/api/authz/evaluate", evalBody("alice", "read", "doc-public", Map.of()));
        assertNotNull(ignored.body());
        JsonNode verify = get("/api/audit/verify");
        assertTrue(verify.get("intact").asBoolean(), verify.get("detail").asText());
        JsonNode records = get("/api/audit/records");
        assertTrue(records.isArray());
        assertFalse(records.isEmpty());
        List<String> required = List.of("sequence", "currentHash", "previousHash",
                "policyVersion", "decision", "contextSummary");
        for (String field : required) {
            assertFalse(records.get(0).get(field).isNull(),
                    "审计记录必须包含 " + field);
        }
    }
}
