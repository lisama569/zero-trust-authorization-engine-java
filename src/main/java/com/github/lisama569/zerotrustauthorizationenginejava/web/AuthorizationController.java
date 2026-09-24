package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.service.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.EvaluationRequestDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** 授权评估接口 */
@RestController
@RequestMapping("/api/authz")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<EvaluationResult> evaluate(@RequestBody EvaluationRequestDto dto) {
        EvaluationRequest request = new EvaluationRequest(
                dto.getSubjectId(),
                dto.getAction(),
                dto.getResourceId(),
                new EnvironmentContext(dto.getEnvironment() == null
                        ? Map.of() : dto.getEnvironment()));
        return ResponseEntity.ok(authorizationService.evaluate(request));
    }
}
