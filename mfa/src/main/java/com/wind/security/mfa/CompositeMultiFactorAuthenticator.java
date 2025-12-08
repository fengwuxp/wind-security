package com.wind.security.mfa;


import com.wind.common.exception.BaseException;
import com.wind.security.mfa.request.MultiFactorAuthenticationRequest;
import org.jspecify.annotations.NonNull;

import java.util.Collection;


/**
 * 组合认证服务
 *
 * @author wuxp
 * @date 2025/12/2 11:21
 **/
public record CompositeMultiFactorAuthenticator(Collection<MultiFactorAuthenticator> delegates) implements MultiFactorAuthenticator {

    public boolean verify(@NonNull MultiFactorAuthenticationRequest request) {
        return delegates.stream()
                .filter(authenticator -> authenticator.supports(request.mfaType()))
                .findFirst()
                .orElseThrow(() -> BaseException.common("unsupported fas type: %s".formatted(request.mfaType())))
                .verify(request);
    }

    @Override
    public boolean supports(@NonNull MultiFactorAuthenticationType fasType) {
        return true;
    }
}
