package com.wind.security.fas;


import org.jspecify.annotations.NonNull;


/**
 * 2fas 认证服务
 *
 * @author wuxp
 * @date 2025-12-02 11:21
 **/
public interface TwoFasAuthenticator {

    /**
     * 验证
     *
     * @param request 二次认证请求
     * @return 是否验证通过
     */
    boolean verify(@NonNull FasAuthenticationRequest request);

    /**
     * @param fasType 验证码类型
     * @return 是否支持
     */
    boolean supports(@NonNull FasAuthenticationType fasType);
}
