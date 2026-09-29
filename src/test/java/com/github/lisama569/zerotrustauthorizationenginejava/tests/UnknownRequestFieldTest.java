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

import static org.junit.jupiter.api.Assertions.*;

/**
 * 调用方请求体夹塞引擎不认识字段时必须被识别并拒绝，不得静默忽略继续算。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UnknownRequestFieldTest {

    private static final Logger log = LoggerFactory.getLogger(UnknownRequestFieldTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @LocalServerPort
    private int port;
    @Autowired
    private TestRestTemplate rest;

    @Test
    @DisplayName("评估请求含未知字段 -> 422 UNKNOWN_FIELD")
    void unknownFieldOnEvaluate() {
        String body = "{\"subjectId\":\"alice\",\"action\":\"read\","
                + "\"resourceId\":\"doc-internal\",\"environment\":{},"
                + "\"impersonateAdmin\":true}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> resp = rest.postForEntity(
                "http://localhost:" + port + "/api/authz/evaluate",
                new HttpEntity<>(body, headers), String.class);
        log.info("未知字段评估请求 -> {} {}", resp.getStatusCode(), resp.getBody());
        assertEquals(422, resp.getStatusCode().value());
        JsonNode node;
        try {
            node = mapper.readTree(resp.getBody());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        assertEquals("UNKNOWN_FIELD", node.get("failureReason").asText());
        assertTrue(node.get("message").asText().contains("impersonateAdmin"));
    }
}
