package org.keycloak.social.wechat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.infinispan.Cache;
import org.infinispan.commons.api.CacheContainerAdmin;
import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.cache.ConfigurationChildBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * 微信用户授权登录实现
 */
public class WechatIdentityProvider extends AbstractOAuth2IdentityProvider<WechatIdentityProviderConfig>
        implements SocialIdentityProvider<WechatIdentityProviderConfig> {
    private static final Logger log = Logger.getLogger(WechatIdentityProvider.class);

    // 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可
    private static final String SCOPE_LOGIN = "snsapi_login";
    private static final String SCOPE_BASE = "snsapi_base";
    private static final String SCOPE_USERINFO = "snsapi_userinfo";

    private static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
    private static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
    private static final String USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo";

    private static final String OAUTH2_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    private static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
    private static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";

    private static final String WECHAT_MP_AUTH_URL_1 = "https://api.weixin.qq.com/sns/jscode2session?appid=";
    private static final String WECHAT_MP_AUTH_URL_2 = "&secret=";
    private static final String WECHAT_MP_AUTH_URL_3 = "&js_code=";
    private static final String WECHAT_MP_AUTH_URL_4 = "&grant_type=authorization_code";

    private static final String WECHAT_ACCESS_TOKEN_URL_1 =
            "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=";
    private static final String WECHAT_ACCESS_TOKEN_URL_2 = "&secret=";

    private static final String WECHAT_USER_AGENT = "micromessenger";
    private static final String WECHAT_REDIRECT_FRAGMENT = "wechat_redirect";
    private static final String HTTP_REDIRECT_LOCATION_HEADER = "X-Redirect-Location";

    private static final String UNION_ID = "unionid";
    private static final String OPEN_ID = "openid";
    private static final String SESSION_KEY = "session_key";
    private static final String APP_ID = "appid";
    private static final String LOGIN_TYPE = "login_type";
    private static final String EXPIRES_IN = "expires_in";

    private static final String WECHAT_CACHE_NAME = "wechatAccessTokens";
    private static final String CACHE_LOCK_PREFIX = "__lock__";
    private final Cache<String, String> tokenCache;
    private final String cacheLockMark;

    public WechatIdentityProvider(KeycloakSession session, WechatIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(USERINFO_URL);
        config.setDefaultScope(SCOPE_LOGIN);

        log.info("Create global cache for wechat access token");
        InfinispanConnectionProvider ispnProvider = session.getProvider(InfinispanConnectionProvider.class);
        EmbeddedCacheManager cacheManager;
        ConfigurationChildBuilder builder = new ConfigurationBuilder();
        if (ispnProvider != null) {
            log.info("Prepare distributed volatile cache with synchronous replication on Infinispan cluster");
            cacheManager = ispnProvider.getCache(InfinispanConnectionProvider.WORK_CACHE_NAME).getCacheManager();
            builder = builder.clustering().cacheMode(CacheMode.REPL_SYNC);
        } else {
            log.warn("Prepare local in-memory Infinispan cache");
            cacheManager = new DefaultCacheManager(new GlobalConfigurationBuilder().nonClusteredDefault().build());
            builder = builder.memory();
        }
        tokenCache = cacheManager.administration().withFlags(CacheContainerAdmin.AdminFlag.VOLATILE)
                                 .getOrCreateCache(WECHAT_CACHE_NAME, builder.build());
        cacheLockMark = CACHE_LOCK_PREFIX +
                        Objects.requireNonNullElse(tokenCache.getCacheManager().getAddress(), "local");
        log.info("WeChat access token cache created, lock mark is " + cacheLockMark);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new WechatEndpoint(callback, realm, event);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getDefaultScopes() {
        return SCOPE_LOGIN;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        final var authSession = request.getAuthenticationSession();

        var loginHint = authSession.getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (loginHint != null) {
            // 微信小程序需要将appid和code编码到loginHint中
            var sep = loginHint.indexOf(' ');
            if (sep > 0) {
                // 微信小程序
                var appId = loginHint.substring(0, sep);
                var code = loginHint.substring(sep + 1);
                log.info("WeChatMP: appid=" + appId + ", code=" + code);

                authSession.setUserSessionNote(APP_ID, appId);
                authSession.setUserSessionNote(LOGIN_TYPE, WechatLoginType.MINI_PROGRAM.name());
                return UriBuilder.fromUri(URI.create(request.getUriInfo().getAbsolutePath() + "/../endpoint"))
                                 .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                                 .queryParam(OAUTH2_PARAMETER_CODE, code);
            } else {
                // 微信公众号可以将appid编码到loginHint中
                authSession.setUserSessionNote(APP_ID, loginHint);
                log.info("WeChatOA: appid=" + loginHint);
            }
        }

        final var config = getConfig();
        final var weChatBrowser = isWechatBrowser(request.getHttpRequest().getHttpHeaders());
        final UriBuilder uriBuilder;
        final WechatLoginType loginType;

        if (weChatBrowser) {
            // 微信公众号
            loginType = WechatLoginType.OFFICIAL_ACCOUNT;
            uriBuilder = UriBuilder.fromUri(OAUTH2_AUTH_URL)
                                   .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getWechatOfficialAccountId())
                                   .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, OAUTH2_PARAMETER_CODE)
                                   .queryParam(OAUTH2_PARAMETER_SCOPE, SCOPE_USERINFO)
                                   .fragment(WECHAT_REDIRECT_FRAGMENT);
        } else {
            var loginUrlForPc = config.getCustomizedLoginUrl();
            if (loginUrlForPc != null && !loginUrlForPc.isEmpty()) {
                // 同时登录微信公众号和第三方网站
                loginType = WechatLoginType.CUSTOMIZED;
                uriBuilder = UriBuilder.fromUri(loginUrlForPc)
                                       .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getWechatOfficialAccountId())
                                       .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, OAUTH2_PARAMETER_CODE)
                                       .queryParam(OAUTH2_PARAMETER_SCOPE, SCOPE_USERINFO);
            } else {
                // 使用微信认证的第三方网站
                loginType = WechatLoginType.BROWSER;
                uriBuilder = UriBuilder.fromUri(AUTH_URL)
                                       .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId())
                                       .queryParam(OAUTH2_PARAMETER_SCOPE, config.getDefaultScope());
            }
        }
        uriBuilder.queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                  .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded());
        authSession.setUserSessionNote(LOGIN_TYPE, loginType.name());
        log.info("LoginType: " + loginType.name());

        if (config.isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        if (config.isUiLocales()) {
            uriBuilder.queryParam(OIDCLoginProtocol.UI_LOCALES_PARAM,
                                  session.getContext().resolveLocale(null).toLanguageTag());
        }

        var prompt = config.getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = authSession.getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        var acr = authSession.getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }

        var nonce = authSession.getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = Base64Url.encode(SecretGenerator.getInstance().randomBytes(16));
            authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        return uriBuilder;
    }

    /**
     * 判断是否在微信浏览器里面请求
     */
    private static boolean isWechatBrowser(HttpHeaders headers) {
        if (headers != null) {
            var ua = headers.getHeaderString("user-agent");
            return ua != null && ua.toLowerCase().contains(WECHAT_USER_AGENT);
        }
        return false;
    }

    private String getAccessToken(String appId) {
        String accessToken = tokenCache.get(appId);
        if (accessToken == null || accessToken.startsWith(CACHE_LOCK_PREFIX)) {
            for (int i = 0; i < 15; i++) {
                accessToken = tokenCache.computeIfAbsent(appId, k -> cacheLockMark, 10000, MILLISECONDS);
                if (!accessToken.startsWith(CACHE_LOCK_PREFIX)) {
                    break;
                }
                if (accessToken.equals(cacheLockMark)) {
                    log.info("WeChat application " + appId + ": refresh access token");
                    var secret = getConfig().getWechatMiniProgramSecret(appId);
                    if (secret == null) {
                        log.warn("Unknown WeChat application: " + appId);
                        break;
                    }

                    JsonNode tokenResponse = null;
                    try {
                        tokenResponse = SimpleHttp
                                .doGet(WECHAT_ACCESS_TOKEN_URL_1 + appId + WECHAT_ACCESS_TOKEN_URL_2 + secret, session)
                                .asJson();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    if (tokenResponse != null) {
                        accessToken = getJsonProperty(tokenResponse, getAccessTokenResponseParameter());
                        int expireInSeconds = Integer.parseInt(getJsonProperty(tokenResponse, EXPIRES_IN)) - 60;
                        tokenCache.put(appId, accessToken, expireInSeconds, SECONDS);
                        break;
                    }
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }
        return accessToken;
    }

    /**
     * 获取登录信息
     */
    public BrokeredIdentityContext getFederatedIdentity(String response, WechatLoginType loginType, String appId) {
        JsonNode profile;
        try {
            profile = new ObjectMapper().readTree(response);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new IdentityBrokerException("Can't parse OAuth server response: " + response);
        }
        log.info("User profile: " + profile.toString());
        var context = extractIdentityFromProfile(profile, appId);

        String accessToken = getJsonProperty(profile, getAccessTokenResponseParameter());
        if (WechatLoginType.MINI_PROGRAM.equals(loginType)) {
            accessToken = getAccessToken(appId);
        }
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }
        log.info("Access token: " + accessToken);
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);

        return context;
    }

    /**
     * 获取用户信息
     */
    protected BrokeredIdentityContext extractIdentityFromProfile(JsonNode profile, String appId) {
        String openId = getJsonProperty(profile, OPEN_ID);
        if (openId == null) {
            throw new IdentityBrokerException("Can't parse unionid/openid from server response: ");
        }
        openId = appId + "-" + openId;

        var user = new BrokeredIdentityContext(openId);
        user.setUsername(openId);
        user.setBrokerUserId(openId);
        user.setModelUsername(openId);
        String unionId = getJsonProperty(profile, UNION_ID);
        if (unionId != null) {
            user.setUserAttribute(UNION_ID, unionId);
        }
        user.setUserAttribute(APP_ID, appId);
        user.setUserAttribute(OPEN_ID, openId);
        user.setUserAttribute(SESSION_KEY, getJsonProperty(profile, SESSION_KEY));
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    /**
     * 微信请求节点
     */
    protected class WechatEndpoint extends Endpoint {
        @Context
        protected UriInfo uriInfo;

        public WechatEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @Override
        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (state == null) {
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
                session.getContext().setAuthenticationSession(authSession);

                if (error != null) {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    if (error.equals(ACCESS_DENIED)) {
                        return callback.cancelled();
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) ||
                               error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        return callback.error(error);
                    } else {
                        return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                if (authorizationCode != null) {
                    final var sessionNotes = authSession.getUserSessionNotes();
                    final var loginType = WechatLoginType.valueOf(sessionNotes.get(LOGIN_TYPE));
                    final var appId = sessionNotes.get(APP_ID);

                    var tokenRequest = generateTokenRequest(authorizationCode, loginType, appId);
                    if (tokenRequest != null) {
                        var response = tokenRequest.asString();
                        logger.info("Response from auth code = " + response);

                        var federatedIdentity = getFederatedIdentity(response, loginType, appId);
                        if (getConfig().isStoreToken() && federatedIdentity.getToken() == null) {
                            // make sure that token wasn't already set by getFederatedIdentity();
                            // want to be able to allow provider to set the token itself.
                            federatedIdentity.setToken(response);
                        }
                        federatedIdentity.setIdpConfig(getConfig());
                        federatedIdentity.setIdp(WechatIdentityProvider.this);
                        federatedIdentity.setAuthenticationSession(authSession);
                        var authenticated = callback.authenticated(federatedIdentity);

                        if (WechatLoginType.MINI_PROGRAM.equals(loginType) &&
                            authenticated.getStatus() == Response.Status.FOUND.getStatusCode()) {
                            // 微信小程序处理不了重定向时生成的Cookie，需要分步处理
                            var location = authenticated.getLocation().toString();
                            authenticated = Response.status(Response.Status.NO_CONTENT)
                                                    .header(HTTP_REDIRECT_LOCATION_HEADER, location)
                                                    .build();
                        }

                        return authenticated;
                    }
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }

            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode, WechatLoginType loginType, String appId) {
            final var config = getConfig();
            String secret;

            if (WechatLoginType.MINI_PROGRAM.equals(loginType)) {
                secret = config.getWechatMiniProgramSecret(appId);
                log.info("WeChatMP: appId=" + appId + ", appSecret=" + secret);
                if (secret != null) {
                    return SimpleHttp
                            .doGet(WECHAT_MP_AUTH_URL_1 + appId + WECHAT_MP_AUTH_URL_2 + secret +
                                   WECHAT_MP_AUTH_URL_3 + authorizationCode + WECHAT_MP_AUTH_URL_4, session);
                }
            } else {
                if (WechatLoginType.BROWSER.equals(loginType)) {
                    appId = config.getClientId();
                    secret = config.getClientSecret();
                } else {
                    if (appId == null) {
                        appId = config.getWechatOfficialAccountId();
                        secret = config.getWechatOfficialAccountSecret();
                    } else {
                        secret = config.getWechatOfficialAccountSecret(appId);
                    }
                }
                log.info("WeChatOA: appId=" + appId + ", appSecret=" + secret);
                if (secret != null) {
                    return SimpleHttp
                            .doPost(TOKEN_URL, session)
                            .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                            .param(OAUTH2_PARAMETER_CLIENT_ID, appId)
                            .param(OAUTH2_PARAMETER_CLIENT_SECRET, secret)
                            .param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
                            .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
                }
            }

            return null;
        }
    }

    public enum WechatLoginType {
        BROWSER,
        OFFICIAL_ACCOUNT,
        MINI_PROGRAM,
        CUSTOMIZED,
    }
}
