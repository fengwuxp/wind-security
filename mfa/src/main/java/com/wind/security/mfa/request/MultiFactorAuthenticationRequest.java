package com.wind.security.mfa.request;


import com.wind.common.exception.AssertUtils;
import com.wind.security.mfa.MultiFactorAuthenticationType;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.io.Serializable;


/**
 * multi factor 请求参数
 *
 * @param userId  用户 ID
 * @param scene   二次认证场景
 * @param mfaType 二次认证类型
 * @param code    二次认证码
 * @author wuxp
 * @date 2025/12/8 11:20
 */
@Builder
public record MultiFactorAuthenticationRequest(@NotNull Serializable userId, @NotNull String scene, @NotNull MultiFactorAuthenticationType mfaType, @NotNull String code) {

    public MultiFactorAuthenticationRequest {
        AssertUtils.notNull(userId, "argument userId must not null");
        AssertUtils.notNull(scene, "argument scene must not null");
        AssertUtils.notNull(mfaType, "argument mfaType must not null");
        AssertUtils.hasText(code, "argument code must not empty");
    }
}
