package com.wind.security.mfa;


import com.wind.security.mfa.request.MultiFactorAuthenticationRequest;
import org.jspecify.annotations.NonNull;


/**
 * 多因子认证服务
 *
 * @author wuxp
 * @date 2025-12-08 10:39
 **/
public interface MultiFactorAuthenticator {

    /**
     * 验证
     *
     * @param request 二次认证请求
     * @return 是否验证通过
     */
    boolean verify(@NonNull MultiFactorAuthenticationRequest request);

    /**
     * @param fasType 验证码类型
     * @return 是否支持
     */
    boolean supports(@NonNull MultiFactorAuthenticationType fasType);
}
