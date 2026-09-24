package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.engine.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 授权评估 REST 接口。 */
@RestController
@RequestMapping("/api/authz")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @PostMapping("/evaluate")
    public DecisionResult evaluate(
            @RequestBody AccessRequest request,
            @RequestHeader(value = "X-Request-Id", required = false) String requestId) {
        return authorizationService.authorize(request, requestId);
    }
}
