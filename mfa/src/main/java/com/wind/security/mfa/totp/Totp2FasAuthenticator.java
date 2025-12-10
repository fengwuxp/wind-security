package com.wind.security.mfa.totp;


import com.wind.security.mfa.MultiFactorAuthenticationType;
import com.wind.security.mfa.MultiFactorAuthenticator;
import com.wind.security.mfa.request.MultiFactorAuthenticationRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import java.util.Objects;
import java.util.function.Function;


/**
 * totp 2fas 认证
 *
 * @author wuxp
 * @date 2025-12-02 11:21
 */
@Slf4j
public record Totp2FasAuthenticator(Function<String, TotpAuthenticator> factory) implements MultiFactorAuthenticator {

    @Override
    public boolean verify(@NonNull MultiFactorAuthenticationRequest request) {
        TotpAuthenticator totpAuthenticator = factory.apply(request.scene());
        return totpAuthenticator.verify(String.valueOf(request.userId()), request.code());
    }

    @Override
    public boolean supports(@NonNull MultiFactorAuthenticationType fasType) {
        return Objects.equals(MultiFactorAuthenticationType.TOTP, fasType);
    }
}
