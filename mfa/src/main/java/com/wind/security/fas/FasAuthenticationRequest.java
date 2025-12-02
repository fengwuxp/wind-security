package com.wind.security.fas;


import com.wind.common.enums.DescriptiveEnum;
import com.wind.common.exception.AssertUtils;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;


/**
 * 二次认证请求参数
 *
 * @param userId  用户 ID
 * @param fasCode 二次认证码
 * @param fasType 二次认证类型
 * @param scene   二次认证场景
 * @author wuxp
 * @date 2025/12/2 11:21
 */
@Builder
public record FasAuthenticationRequest(@NotNull String userId, @NotNull String fasCode, @NotNull FasAuthenticationType fasType, @NotNull DescriptiveEnum scene) {

    public FasAuthenticationRequest {
        AssertUtils.notNull(userId, "argument userId must not null");
        AssertUtils.hasText(fasCode, "argument fasCode must not empty");
        AssertUtils.notNull(fasType, "argument fasType must not null");
        AssertUtils.notNull(scene, "argument scene must not null");
    }
}
