package com.wind.security.authentication.jwt;

import com.wind.common.WindHttpConstants;
import com.wind.common.enums.WindClientDeviceType;
import com.wind.common.exception.AssertUtils;
import com.wind.security.authentication.AuthenticationTokenCodecService;
import com.wind.security.authentication.AuthenticationTokenUserMapFactory;
import com.wind.security.authentication.WindAuthenticationToken;
import com.wind.security.authentication.WindAuthenticationUser;
import com.wind.security.jwt.JwtTokenCodec;
import com.wind.web.util.ClientDeviceTypeParserUtils;
import com.wind.web.util.HttpServletRequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Objects;

import static com.wind.common.WindHttpConstants.HTTP_REQUEST_CLIENT_DEVICE_TYPE_HEADER_NAME;

/**
 * @author wuxp
 * @date 2025-05-20 14:38
 **/
@Slf4j
@AllArgsConstructor
public class DefaultJwtAuthenticationTokenCodecService implements AuthenticationTokenCodecService {

    private final JwtTokenCodec jwtTokenCodec;

    private final AuthenticationTokenUserMapFactory factory;

    @Override
    public WindAuthenticationToken generateToken(WindAuthenticationUser user, Duration ttl) {
        WindAuthenticationToken result = jwtTokenCodec.encoding(user, ttl);
        factory.userToken(parseClientDeviceType()).put(String.valueOf(user.id()), result.id());
        return result;
    }

    @Override
    public WindAuthenticationToken generateRefreshToken(String userId, Duration ttl) {
        WindAuthenticationToken result = jwtTokenCodec.encodingRefreshToken(userId, ttl);
        factory.refreshToken(parseClientDeviceType()).put(userId, result.id());
        return result;
    }

    @Override
    public WindAuthenticationToken parseAndValidateToken(String accessToken) {
        if (accessToken.startsWith(WindHttpConstants.API_TOKEN_BEARER_PREFIX)) {
            accessToken = accessToken.substring(WindHttpConstants.API_TOKEN_BEARER_PREFIX.length());
        }
        WindAuthenticationToken result = jwtTokenCodec.parse(accessToken);
        String tokenId = factory.userToken(parseClientDeviceType()).getTokenId(result.subject());
        AssertUtils.hasText(tokenId, "invalid access token user");
        AssertUtils.isTrue(Objects.equals(tokenId, result.id()), "invalid access token");
        return result;
    }

    @Override
    public WindAuthenticationToken parseAndValidateRefreshToken(String refreshToken) {
        WindAuthenticationToken result = jwtTokenCodec.parseRefreshToken(refreshToken);
        String tokenId = factory.refreshToken(parseClientDeviceType()).getTokenId(result.subject());
        AssertUtils.hasText(tokenId, "invalid refresh token user");
        AssertUtils.isTrue(Objects.equals(tokenId, result.id()), "invalid refresh token");
        return result;
    }

    @Override
    public void revokeAllToken(String userId) {
        try {
            factory.userToken(parseClientDeviceType()).removeTokenId(userId);
        } catch (Exception ignore) {
            // ignore
        }
        factory.refreshToken(parseClientDeviceType()).removeTokenId(userId);
    }

    private WindClientDeviceType parseClientDeviceType() {
        HttpServletRequest request = HttpServletRequestUtils.getContextRequestOfNullable();
        if (request == null) {
            // 为了测试用例能正常执行
            return WindClientDeviceType.UNKNOWN;
        }
        String deviceType = HttpServletRequestUtils.getHeader(HTTP_REQUEST_CLIENT_DEVICE_TYPE_HEADER_NAME);
        if (StringUtils.hasText(deviceType)) {
            return WindClientDeviceType.valueOf(deviceType);
        }
        return ClientDeviceTypeParserUtils.resolveDeviceType(request);
    }

}
