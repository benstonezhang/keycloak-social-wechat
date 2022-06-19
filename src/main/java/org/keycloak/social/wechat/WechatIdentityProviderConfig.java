package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WechatIdentityProviderConfig extends OAuth2IdentityProviderConfig {
    private static final String WECHAT_OFFICIAL_ACCOUNT_ID = "wechatOfficialAccountId";
    private static final String WECHAT_OFFICIAL_ACCOUNT_SECRET = "wechatOfficialAccountSecret";

    private static final String WECHAT_MINI_PROGRAM_ID = "wechatMiniProgramId";
    private static final String WECHAT_MINI_PROGRAM_SECRET = "wechatMiniProgramSecret";

    private static final String CUSTOMIZED_LOGIN_URL_FOR_PC = "customizedLoginUrl";

    public WechatIdentityProviderConfig() {
        super();
    }

    public WechatIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public void setWechatOfficialAccountId(String appid) {
        getConfig().put(WECHAT_OFFICIAL_ACCOUNT_ID, appid);
    }

    public String getWechatOfficialAccountId() {
        return getConfig().get(WECHAT_OFFICIAL_ACCOUNT_ID);
    }

    public void setWechatOfficialAccountSecret(String secret) {
        getConfig().put(WECHAT_OFFICIAL_ACCOUNT_SECRET, secret);
    }

    public String getWechatOfficialAccountSecret() {
        return getConfig().get(WECHAT_OFFICIAL_ACCOUNT_SECRET);
    }

    public void setWechatMiniProgramId(String appid) {
        getConfig().put(WECHAT_MINI_PROGRAM_ID, appid);
    }

    public String getWechatMiniProgramId() {
        return getConfig().get(WECHAT_MINI_PROGRAM_ID);
    }

    public void setWechatMiniProgramSecret(String secret) {
        getConfig().put(WECHAT_MINI_PROGRAM_SECRET, secret);
    }

    public String getWechatMiniProgramSecret() {
        return getConfig().get(WECHAT_MINI_PROGRAM_SECRET);
    }

    public void setCustomizedLoginUrl(String url) {
        getConfig().put(CUSTOMIZED_LOGIN_URL_FOR_PC, url);
    }

    public String getCustomizedLoginUrl() {
        return getConfig().get(CUSTOMIZED_LOGIN_URL_FOR_PC);
    }
}
