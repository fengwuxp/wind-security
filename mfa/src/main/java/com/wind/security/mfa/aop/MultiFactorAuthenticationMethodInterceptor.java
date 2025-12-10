package com.wind.security.mfa.aop;

import com.wind.common.exception.AssertUtils;
import com.wind.security.mfa.MultiFactorAuthenticationStateManager;
import com.wind.security.mfa.MultiFactorAuthenticationType;
import com.wind.security.mfa.MultiFactorAuthenticator;
import com.wind.security.mfa.request.MultiFactorAuthenticationOwnerKey;
import com.wind.security.mfa.request.MultiFactorAuthenticationRequest;
import com.wind.sentinel.util.SentinelFlowLimitUtils;
import com.wind.web.util.HttpServletRequestUtils;
import com.wind.web.util.HttpTraceVariableUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.io.Serializable;
import java.util.function.Supplier;

import static com.wind.security.mfa.MfaConstants.MFA_CODE_HEADER_NAME;
import static com.wind.security.mfa.MfaConstants.MFA_TYPE_HEADER_NAME;
import static com.wind.security.mfa.MfaConstants.createMfaResource;

/**
 * 多因子认证方法拦截器，需要再 web 上下文中使用
 *
 * @author wuxp
 * @date 2025-12-08 13:02
 **/
@Slf4j
@AllArgsConstructor
public class MultiFactorAuthenticationMethodInterceptor implements MethodInterceptor {

    private final MultiFactorAuthenticator authenticator;

    private final MultiFactorAuthenticationStateManager authenticationStateManager;

    private final Supplier<Serializable> uerIdSupplier;

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        MultiFactorAuthentication authentication = AnnotatedElementUtils.getMergedAnnotation(invocation.getMethod(), MultiFactorAuthentication.class);
        if (authentication != null) {
            handleFasAuthentication(authentication);
        }
        return invocation.proceed();
    }

    private void handleFasAuthentication(MultiFactorAuthentication authentication) {
        HttpServletRequest request = HttpServletRequestUtils.requireContextRequest();
        Serializable userId = uerIdSupplier.get();
        String scene = authentication.value();
        log.debug("Required multi factor authentication userId = {}, scene = {}", userId, scene);

        SentinelFlowLimitUtils.limit(createMfaResource(userId), () -> {
            MultiFactorAuthenticationOwnerKey ownerKey = MultiFactorAuthenticationOwnerKey.builder()
                    .userId(userId)
                    .scene(scene)
                    .ip(HttpTraceVariableUtils.getRequestSourceIp())
                    .deviceId(HttpTraceVariableUtils.getRequestDeviceId())
                    .build();
            if (!authenticationStateManager.isAuthenticated(ownerKey)) {
                String code = request.getHeader(MFA_CODE_HEADER_NAME);
                String mfaType = request.getHeader(MFA_TYPE_HEADER_NAME);
                AssertUtils.hasText(code, "maf authentication code must not empty");
                AssertUtils.hasText(mfaType, "maf authentication type must not empty");
                MultiFactorAuthenticationRequest fasAuthenticationRequest = MultiFactorAuthenticationRequest.builder()
                        .userId(userId)
                        .code(code)
                        .mfaType(MultiFactorAuthenticationType.valueOf(mfaType))
                        .scene(scene)
                        .build();
                AssertUtils.isTrue(authenticator.verify(fasAuthenticationRequest), "MFA 验证码错误");
                authenticationStateManager.authenticate(ownerKey);
            }
        });
    }


}
