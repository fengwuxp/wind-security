package com.wind.security.authentication.jwt;

import com.wind.common.WindHttpConstants;
import com.wind.common.enums.WindClientDeviceType;
import com.wind.common.exception.BaseException;
import com.wind.security.authentication.AuthenticationTokenCodecService;
import com.wind.security.authentication.AuthenticationTokenUserMapFactory;
import com.wind.security.authentication.WindAuthenticationToken;
import com.wind.security.authentication.WindAuthenticationUser;
import com.wind.security.authentication.CaffeineAuthenticationTokenUserMapFactory;
import com.wind.security.jwt.JwtTokenCodec;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;

/**
 * @author wuxp
 * @date 2025-05-20 15:15
 **/
class DefaultJwtAuthenticationTokenCodecServiceTests {

    private final  AuthenticationTokenUserMapFactory factory = createFactory();

    private final AuthenticationTokenCodecService tokenCodecService = createCodeService(factory);

    @Test
    void testGenerateToken() {
        WindAuthenticationToken token = tokenCodecService.generateToken(new WindAuthenticationUser(1L, RandomStringUtils.secure().nextAlphabetic(12)));
        WindAuthenticationToken parsed = tokenCodecService.parseAndValidateToken(token.tokenValue());
        Assertions.assertEquals(token.id(), parsed.id());
        Assertions.assertEquals(token.subject(), parsed.subject());
    }

    @Test
    void testGenerateTokenWithBearer() {
        WindAuthenticationToken token = tokenCodecService.generateToken(new WindAuthenticationUser(1L, RandomStringUtils.secure().nextAlphabetic(12)));
        WindAuthenticationToken parsed = tokenCodecService.parseAndValidateToken(WindHttpConstants.API_TOKEN_BEARER_PREFIX + token.tokenValue());
        Assertions.assertEquals(token.id(), parsed.id());
        Assertions.assertEquals(token.subject(), parsed.subject());
    }

    @Test
    void testParseAndValidateTokenWithException() {
        WindAuthenticationToken token = tokenCodecService.generateToken(new WindAuthenticationUser(1L, RandomStringUtils.secure().nextAlphabetic(12)));
        factory.userToken(WindClientDeviceType.UNKNOWN).remove(token.subject());
        String accessToken = token.tokenValue();
        BaseException exception = Assertions.assertThrows(BaseException.class, () -> tokenCodecService.parseAndValidateToken(accessToken));
        Assertions.assertEquals("invalid access token user", exception.getMessage());
    }

    @Test
    void testGenerateRefreshToken() {
        WindAuthenticationToken token = tokenCodecService.generateRefreshToken("1");
        WindAuthenticationToken parsed = tokenCodecService.parseAndValidateRefreshToken(token.tokenValue());
        Assertions.assertEquals(token.id(), parsed.id());
        Assertions.assertEquals(token.subject(), parsed.subject());
    }

    @Test
    void testParseAndValidateRefreshTokenWithException() {
        WindAuthenticationToken token = tokenCodecService.generateRefreshToken("1");
        tokenCodecService.revokeAllToken(token.subject());
        String refreshToken = token.tokenValue();
        BaseException exception = Assertions.assertThrows(BaseException.class, () -> tokenCodecService.parseAndValidateRefreshToken(refreshToken));
        Assertions.assertEquals("invalid refresh token user", exception.getMessage());
    }

    private AuthenticationTokenCodecService createCodeService(AuthenticationTokenUserMapFactory factory) {
        JwtTokenCodec tokenCodec = JwtTokenCodecTests.createCodec(JwtTokenCodecTests.jwtProperties(Duration.ofHours(1)));
        return new DefaultJwtAuthenticationTokenCodecService(tokenCodec, factory);
    }

    private AuthenticationTokenUserMapFactory createFactory() {
        return new CaffeineAuthenticationTokenUserMapFactory(new JwtProperties());
    }
}
