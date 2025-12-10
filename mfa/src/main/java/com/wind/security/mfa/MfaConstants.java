package com.wind.security.mfa;

import com.alibaba.csp.sentinel.EntryType;
import com.wind.common.util.ServiceInfoUtils;
import com.wind.security.mfa.aop.MultiFactorAuthentication;
import com.wind.sentinel.DefaultSentinelResource;
import com.wind.sentinel.SentinelResource;
import com.wind.web.util.HttpTraceVariableUtils;
import org.jspecify.annotations.NonNull;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * @author wuxp
 * @date 2025-12-10 16:05
 **/
public final class MfaConstants {

    private MfaConstants() {
        throw new AssertionError();
    }

    /**
     * MFA 验证码请求头名称
     */
    public static final String MFA_CODE_HEADER_NAME = "Maf-Code";

    /**
     * MFA 验证类型请求头名称
     */
    public static final String MFA_TYPE_HEADER_NAME = "Maf-Type";

    @NonNull
    public static SentinelResource createMfaResource(@NonNull Serializable userId) {
        DefaultSentinelResource result = new DefaultSentinelResource();
        result.setName(MultiFactorAuthentication.class.getName());
        result.setResourceType(40401);
        result.setContextName(ServiceInfoUtils.getApplicationName());
        result.setOrigin(HttpTraceVariableUtils.getRequestSourceIp());
        result.setEntryType(EntryType.IN);
        result.setArgs(List.of(
                userId,
                Objects.requireNonNull(HttpTraceVariableUtils.getRequestSourceIp()),
                Objects.requireNonNull(HttpTraceVariableUtils.getRequestDeviceId())
        ));
        return result;
    }
}
