package org.keycloak.social.wechat;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

import static org.keycloak.social.wechat.WechatIdentityProviderConfig.*;

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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder
                .create()
                .property(WECHAT_OFFICIAL_ACCOUNT_ID, "Official Account AppId",
                          "WeChat AppId for Official Account",
                          ProviderConfigProperty.STRING_TYPE, null, null, false)
                .property(WECHAT_OFFICIAL_ACCOUNT_SECRET, "Official Account Secret",
                          "WeChat App Secret for Official Account",
                          ProviderConfigProperty.PASSWORD, null, null, true)
                .property(WECHAT_MINI_PROGRAM_ID, "Mini Program AppId",
                          "WeChat AppId for Mini Program",
                          ProviderConfigProperty.STRING_TYPE, null, null, false)
                .property(WECHAT_MINI_PROGRAM_SECRET, "Mini Program Secret",
                          "WeChat App Secret for Mini Program",
                          ProviderConfigProperty.PASSWORD, null, null, true)
                .property(CUSTOMIZED_LOGIN_URL_FOR_PC, "Customized Login Url",
                          "Customized Url for login and favorite",
                          ProviderConfigProperty.STRING_TYPE, null, null, false)
                .build();
    }
}
