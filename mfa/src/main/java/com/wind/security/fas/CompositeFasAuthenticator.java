package com.wind.security.fas;


import com.wind.common.exception.BaseException;
import org.jspecify.annotations.NonNull;

import java.util.Collection;


/**
 * 组合认证服务
 *
 * @author wuxp
 * @date 2025/12/2 11:21
 **/
public record CompositeFasAuthenticator(Collection<TwoFasAuthenticator> delegates) implements TwoFasAuthenticator {

    public boolean verify(@NonNull FasAuthenticationRequest request) {
        return delegates.stream()
                .filter(authenticator -> authenticator.supports(request.fasType()))
                .findFirst()
                .orElseThrow(() -> BaseException.common("unsupported fas type: %s".formatted(request.fasType())))
                .verify(request);
    }

    @Override
    public boolean supports(@NonNull FasAuthenticationType fasType) {
        return true;
    }
}
