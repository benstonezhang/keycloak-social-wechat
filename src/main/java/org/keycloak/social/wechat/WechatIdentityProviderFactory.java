package org.keycloak.social.wechat;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class WechatIdentityProviderFactory extends AbstractIdentityProviderFactory<WechatIdentityProvider>
        implements SocialIdentityProviderFactory<WechatIdentityProvider> {
    public static final String PROVIDER_ID = "wechat";

    @Override
    public String getName() {
        return "WeChat";
    }

    @Override
    public WechatIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WechatIdentityProvider(session, new WechatIdentityProviderConfig(model));
    }

    @Override
    public WechatIdentityProviderConfig createConfig() {
        return new WechatIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
