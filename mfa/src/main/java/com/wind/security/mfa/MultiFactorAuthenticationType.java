package com.wind.security.mfa;

import com.wind.common.enums.DescriptiveEnum;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * MFA 认证类型
 *
 * @author wuxp
 * @date 2025-02-08 15:07
 */
@AllArgsConstructor
@Getter
public enum MultiFactorAuthenticationType implements DescriptiveEnum {

    /**
     * totp
     */
    TOTP("TOTP"),

    /**
     * 验证码
     */
    SMS("短信"),

    /**
     * 邮箱
     */
    EMAIL("邮件");

    private final String desc;

}
