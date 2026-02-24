package com.wind.security.authentication;

import com.wind.common.enums.WindClientDeviceType;
import org.jspecify.annotations.NonNull;

/**
 * 认证 token id 和用户关系的 map 工厂
 *
 * @author wuxp
 * @date 2026-02-24 10:39
 **/
public interface AuthenticationTokenUserMapFactory {

    /**
     * 获取 user token id 和用户关系的 map
     *
     * @param deviceType 设备类型
     * @return user token id 和用户关系的 {@link AuthenticationTokenUserMap} 实例
     */
    @NonNull
    AuthenticationTokenUserMap userToken(@NonNull WindClientDeviceType deviceType);

    /**
     * 获取 refresh token id 和用户关系的 map
     *
     * @param deviceType 设备类型
     * @return 刷新 token id 和用户关系的 {@link AuthenticationTokenUserMap} 实例
     */
    @NonNull
    AuthenticationTokenUserMap refreshToken(@NonNull WindClientDeviceType deviceType);
}
