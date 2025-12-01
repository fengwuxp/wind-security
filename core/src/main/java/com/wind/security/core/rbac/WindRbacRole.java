package com.wind.security.core.rbac;

import com.wind.integration.core.resources.WindResources;
import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;
import java.util.Set;

/**
 * wind-rbac 角色定义
 *
 * @param <ID> id
 * @author wuxp
 * @date 2025-11-26 18:10
 **/
public interface WindRbacRole<ID extends Serializable> extends WindResources<ID> {

    /**
     * @return 权限所属者
     */
    @NotBlank
    String getOwner();

    /**
     * @return 权限所属组
     */
    @NotBlank
    String getGroup();

    /**
     * 角色绑定的权限 id 集合
     *
     * @return 权限ids
     */
    Set<ID> getPermissionIds();
}
