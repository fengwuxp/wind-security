package com.wind.security.fas;


import com.wind.common.enums.DescriptiveEnum;
import com.wind.security.mfa.TotpAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import java.util.Objects;
import java.util.function.Function;

/**
 * MFA 二次认证
 *
 * @author gongjin
 * @date 2025-02-08 12:39
 **/
@Slf4j
public record MfaFasAuthenticator(Function<DescriptiveEnum, TotpAuthenticator> factory) implements TwoFasAuthenticator {

    @Override
    public boolean verify(FasAuthenticationRequest request) {
        TotpAuthenticator totpAuthenticator = factory.apply(request.scene());
        return totpAuthenticator.verify(String.valueOf(request.userId()), request.fasCode());
    }

    @Override
    public boolean supports(@NonNull FasAuthenticationType fasType) {
        return Objects.equals(FasAuthenticationType.MFA, fasType);
    }
}
