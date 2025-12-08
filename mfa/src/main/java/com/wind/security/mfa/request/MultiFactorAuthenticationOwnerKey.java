package com.wind.security.mfa.request;

import com.wind.common.exception.AssertUtils;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.Serializable;

/**
 * MFA 认证用户密钥
 *
 * @param userId   用户 ID
 * @param scene    认证场景
 * @param ip       请求 ip
 * @param deviceId 设备 id
 * @author wuxp
 * @date 2025-12-08 11:10
 */
@Builder
public record MultiFactorAuthenticationOwnerKey(@NotNull Serializable userId, @NotNull String scene, @NotNull String ip, @Nullable String deviceId) {

    public MultiFactorAuthenticationOwnerKey {
        AssertUtils.notNull(userId, "argument userId must not null");
        AssertUtils.hasText(scene, "argument scene must not empty");
        AssertUtils.hasText(ip, "argument ip must not empty");
    }

    @NonNull
    public String getKey() {
        return "%s:%s@%s_%s".formatted(userId, scene, ip, deviceId);
    }
}
