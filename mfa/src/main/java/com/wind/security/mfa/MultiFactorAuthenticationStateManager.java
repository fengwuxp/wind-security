package com.wind.security.mfa;


import com.wind.security.mfa.request.MultiFactorAuthenticationOwnerKey;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

import java.io.Serializable;
import java.time.Duration;

/**
 * 多因子认证状态管理器
 *
 * @author wuxp
 * @date 2025-12-08 10:39
 **/
public interface MultiFactorAuthenticationStateManager {

    /**
     * 标记用户为已认证
     *
     * @param ownerKey 认证用户标识
     */
    default void authenticate(@NotNull MultiFactorAuthenticationOwnerKey ownerKey) {
        authenticate(ownerKey, null);
    }

    /**
     * 标记用户为已认证
     *
     * @param ownerKey 认证用户标识
     * @param ttl      认证有效期，为空则使用默认有效期
     */
    void authenticate(@NotNull MultiFactorAuthenticationOwnerKey ownerKey, @Nullable Duration ttl);

    /**
     * 撤销用户认证
     *
     * @param ownerKey 认证用户标识
     */
    void unAuthenticate(@NotNull MultiFactorAuthenticationOwnerKey ownerKey);

    /**
     * 是否认证
     *
     * @param userId 用户 ID
     * @param scene  认证场景
     * @return true:已认证
     */
    default boolean isAuthenticated(@NotNull Serializable userId, @NotNull String scene) {
        return isAuthenticated(MultiFactorAuthenticationOwnerKey.of(userId, scene));
    }

    /**
     * 是否认证
     *
     * @param ownerKey 认证用户标识
     * @return true:已认证
     */
    boolean isAuthenticated(@NotNull MultiFactorAuthenticationOwnerKey ownerKey);
}
