package com.wind.security.authentication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.wind.common.WindConstants;
import com.wind.common.caffine.CaffeineConcurrentMap;
import com.wind.common.enums.WindClientDeviceType;
import com.wind.security.authentication.jwt.JwtProperties;
import lombok.AllArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * caffeine 缓存实现
 *
 * @author wuxp
 * @date 2026-02-24 10:40
 **/
@AllArgsConstructor
public class CaffeineAuthenticationTokenUserMapFactory implements AuthenticationTokenUserMapFactory {

    private final Map<String, ConcurrentMap<String, String>> userTokenCaches = new ConcurrentHashMap<>();

    private final Map<String, ConcurrentMap<String, String>> refreshTokenCaches = new ConcurrentHashMap<>();

    private final JwtProperties properties;

    @Override
    public @NonNull ConcurrentMap<String, String> userToken(@NonNull WindClientDeviceType deviceType) {
        String name = properties.isAllowMultiDevicePerType() ? deviceType.name() : WindConstants.DEFAULT_TEXT;
        return userTokenCaches.computeIfAbsent(name, k -> {
            Cache<String, String> cache = Caffeine.newBuilder()
                    .expireAfterWrite(properties.getEffectiveTime())
                    .build();
            return new CaffeineConcurrentMap<>(cache);
        });
    }

    @Override
    public @NonNull ConcurrentMap<String, String> refreshToken(@NonNull WindClientDeviceType deviceType) {
        String name = properties.isAllowMultiDevicePerType() ? deviceType.name() : WindConstants.DEFAULT_TEXT;
        return refreshTokenCaches.computeIfAbsent(name, k -> {
            Cache<String, String> cache = Caffeine.newBuilder()
                    .expireAfterWrite(properties.getRefreshEffectiveTime())
                    .build();
            return new CaffeineConcurrentMap<>(cache);
        });
    }
}
