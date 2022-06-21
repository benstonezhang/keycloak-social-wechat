package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.HashMap;
import java.util.Map;

public class WechatIdentityProviderConfig extends OAuth2IdentityProviderConfig {
    private static final String WECHAT_OFFICIAL_ACCOUNT_ID = "wechatOfficialAccountId";
    private static final String WECHAT_OFFICIAL_ACCOUNT_SECRET = "wechatOfficialAccountSecret";

    private static final String WECHAT_MINI_PROGRAM_ID = "wechatMiniProgramId";
    private static final String WECHAT_MINI_PROGRAM_SECRET = "wechatMiniProgramSecret";

    private static final String CUSTOMIZED_LOGIN_URL_FOR_PC = "customizedLoginUrl";

    private Map<String, String> weChatMpApps = null;

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
        weChatMpApps = null;
        getConfig().put(WECHAT_MINI_PROGRAM_ID, appid);
    }

    public String getWechatMiniProgramId() {
        return getConfig().get(WECHAT_MINI_PROGRAM_ID);
    }

    public void setWechatMiniProgramSecret(String secret) {
        weChatMpApps = null;
        getConfig().put(WECHAT_MINI_PROGRAM_SECRET, secret);
    }

    public String getWechatMiniProgramSecret() {
        return getConfig().get(WECHAT_MINI_PROGRAM_SECRET);
    }

    public String getWechatMiniProgramSecret(String appId) {
        if (weChatMpApps == null) {
            parseAppIdAndSecret();
        }
        return weChatMpApps.get(appId);
    }

    public Map<String, String> fetchWeChatMpApps() {
        return weChatMpApps;
    }

    public void setCustomizedLoginUrl(String url) {
        getConfig().put(CUSTOMIZED_LOGIN_URL_FOR_PC, url);
    }

    public String getCustomizedLoginUrl() {
        return getConfig().get(CUSTOMIZED_LOGIN_URL_FOR_PC);
    }

    private void parseAppIdAndSecret() {
        weChatMpApps = new HashMap<>();
        var appIds = getConfig().get(WECHAT_MINI_PROGRAM_ID).split(",");
        var secrets = getConfig().get(WECHAT_MINI_PROGRAM_SECRET).split(",");
        var count = Math.min(appIds.length, secrets.length);
        for (int i = 0; i < count; i++) {
            var appId = appIds[i].trim();
            var secret = secrets[i].trim();
            if ((!appId.isEmpty()) && (!secret.isEmpty())) {
                weChatMpApps.put(appId, secret);
            }
        }
    }
}
