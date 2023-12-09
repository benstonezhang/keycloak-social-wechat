package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.HashMap;
import java.util.Map;

public class WechatIdentityProviderConfig extends OAuth2IdentityProviderConfig {
    static final String WECHAT_OFFICIAL_ACCOUNT_ID = "wechatOfficialAccountId";
    static final String WECHAT_OFFICIAL_ACCOUNT_SECRET = "wechatOfficialAccountSecret";
    static final String WECHAT_MINI_PROGRAM_ID = "wechatMiniProgramId";
    static final String WECHAT_MINI_PROGRAM_SECRET = "wechatMiniProgramSecret";
    static final String CUSTOMIZED_LOGIN_URL_FOR_PC = "customizedLoginUrl";

    private static final String LIST_SPLIT_REGEX = "(,|;)";

    private Map<String, String> weChatOaApps = null;
    private Map<String, String> weChatMpApps = null;

    public WechatIdentityProviderConfig() {
        super();
    }

    public WechatIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public void setWechatOfficialAccountId(String appid) {
        weChatOaApps = null;
        getConfig().put(WECHAT_OFFICIAL_ACCOUNT_ID, appid);
    }

    public String getWechatOfficialAccountId() {
        return getConfig().get(WECHAT_OFFICIAL_ACCOUNT_ID);
    }

    public void setWechatOfficialAccountSecret(String secret) {
        weChatOaApps = null;
        getConfig().put(WECHAT_OFFICIAL_ACCOUNT_SECRET, secret);
    }

    public String getWechatOfficialAccountSecret() {
        return getConfig().get(WECHAT_OFFICIAL_ACCOUNT_SECRET);
    }

    public String getWechatOfficialAccountSecret(String appId) {
        if (weChatOaApps == null) {
            weChatOaApps = new HashMap<>();
            parseAppIdAndSecret(weChatOaApps, getConfig().get(WECHAT_OFFICIAL_ACCOUNT_ID),
                                getConfig().get(WECHAT_OFFICIAL_ACCOUNT_SECRET));
        }
        return weChatOaApps.get(appId);
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
            weChatMpApps = new HashMap<>();
            parseAppIdAndSecret(weChatMpApps, getConfig().get(WECHAT_MINI_PROGRAM_ID),
                                getConfig().get(WECHAT_MINI_PROGRAM_SECRET));
        }
        return weChatMpApps.get(appId);
    }

    public void setCustomizedLoginUrl(String url) {
        getConfig().put(CUSTOMIZED_LOGIN_URL_FOR_PC, url);
    }

    public String getCustomizedLoginUrl() {
        return getConfig().get(CUSTOMIZED_LOGIN_URL_FOR_PC);
    }

    private static void parseAppIdAndSecret(Map<String, String> apps, String ids, String secrets) {
        var appIds = ids.split(LIST_SPLIT_REGEX);
        var appSecrets = secrets.split(LIST_SPLIT_REGEX);
        for (int i = 0; i < Math.min(appIds.length, appSecrets.length); i++) {
            var appId = appIds[i].trim();
            var appSecret = appSecrets[i].trim();
            if ((!appId.isEmpty()) && (!appSecret.isEmpty())) {
                apps.put(appId, appSecret);
            }
        }
    }
}
