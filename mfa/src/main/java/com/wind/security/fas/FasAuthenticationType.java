package com.wind.security.fas;

import com.wind.common.enums.DescriptiveEnum;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 二次认证类型
 *
 * @author wuxp
 * @date 2025-02-08 15:07
 */
@AllArgsConstructor
@Getter
public enum FasAuthenticationType implements DescriptiveEnum {

    /**
     * MFA
     */
    MFA("2FAS"),

    /**
     * 验证码
     */
    MOBILE("短信"),

    /**
     * 邮箱
     */
    EMAIL("邮件");

    private final String desc;

}
