package com.wind.security.mfa.aop;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 多因子认证注解
 *
 * @author wuxp
 * @date 2025-12-08 11:20
 **/
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface MultiFactorAuthentication {

    /**
     * 认证场景
     *
     * @return mfa 认证场景
     */
    String value();
}
