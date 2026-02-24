package com.wind.security.authentication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.wind.common.WindConstants;
import com.wind.common.enums.WindClientDeviceType;
import com.wind.security.authentication.jwt.JwtProperties;
import lombok.AllArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * caffeine 缓存实现
 *
 * @author wuxp
 * @date 2026-02-24 10:40
 **/
@AllArgsConstructor
public class CaffeineAuthenticationTokenUserMapFactory implements AuthenticationTokenUserMapFactory {

    private final Map<String, AuthenticationTokenUserMap> userTokenCaches = new ConcurrentHashMap<>();

    private final Map<String, AuthenticationTokenUserMap> refreshTokenCaches = new ConcurrentHashMap<>();

    private final JwtProperties properties;

    @Override
    public @NonNull AuthenticationTokenUserMap userToken(@NonNull WindClientDeviceType deviceType) {
        String name = properties.isAllowMultiDevicePerType() ? deviceType.name() : WindConstants.DEFAULT_TEXT;
        return userTokenCaches.computeIfAbsent(name, k -> {
            Cache<String, String> cache = Caffeine.newBuilder()
                    .expireAfterWrite(properties.getEffectiveTime())
                    .build();
            return new CaffeineAuthenticationTokenUserMap(cache);
        });
    }

    @Override
    public @NonNull AuthenticationTokenUserMap refreshToken(@NonNull WindClientDeviceType deviceType) {
        String name = properties.isAllowMultiDevicePerType() ? deviceType.name() : WindConstants.DEFAULT_TEXT;
        return refreshTokenCaches.computeIfAbsent(name, k -> {
            Cache<String, String> cache = Caffeine.newBuilder()
                    .expireAfterWrite(properties.getRefreshEffectiveTime())
                    .build();
            return new CaffeineAuthenticationTokenUserMap(cache);
        });
    }


    private record CaffeineAuthenticationTokenUserMap(Cache<String, String> cache) implements AuthenticationTokenUserMap {

        @Override
        public void put(String userId, String tokenId) {
            cache.put(userId, tokenId);
        }

        @Override
        public @Nullable String getTokenId(String userId) {
            return cache.getIfPresent(userId);
        }

        @Override
        public void removeTokenId(String userId) {
            cache.invalidate(userId);
        }
    }
}
