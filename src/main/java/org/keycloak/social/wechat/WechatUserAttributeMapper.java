package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

/**
 * User attribute mapper
 */
public class WechatUserAttributeMapper extends AbstractJsonUserAttributeMapper {
    private static final String[] cp = new String[]{WechatIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return "wechat-user-attribute-mapper";
    }
}
