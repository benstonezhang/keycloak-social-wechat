# keycloak-social-wechat
Works:
- add Infinispan based cache for WeChat access token
- adapter to WeChat mini program login
- support more than one appid

## Reference
Artifact here is based on work from 
[jyqq163](https://github.com/jyqq163/keycloak-services-social-weixin),
[kkzxak47](https://github.com/kkzxak47/keycloak-services-social-wechatwork) and 
[Jeff-Tian](https://github.com/Jeff-Tian/keycloak-services-social-weixin).
Credit goes to them.

## Usage
For WeChat Mini Program login, client should go through below steps:
- get **CODE** by wx.login()
- generate **STATE_UUID**
- client GET fetch
> /realms/*REALM*/protocol/openid-connect/auth?client_id=*CLIENT_ID*&redirect_uri=*REDIRECT_URI*&state=**STATE_UUID**&response_mode=fragment&response_type=code&scope=openid&login_hint=**APP_ID**%20**CODE**
- keycloak server create a new session and redirect to
> /realms/*REALM*/login-actions/authenticate?client_id=*CLIENT_ID*&tab_id=*TAB_ID*
- client fetch the HTML page as text
- client search string **id="social-wechat"**, then **href="**
- the href looks like
> /realms/*REALM*/broker/wechat/login?client_id=*CLIENT_ID*&amp;tab_id=*TAB_ID*&amp;session_code=*SESSION_CODE*
- client GET fetch this link
- keycloak server redirect to /realms/*REALM*/broker/wechat/endpoint
- keycloak server wechat endpoint connect to Tencent authentication server to get openid and optional unionid
- if this is the first login, keycloak server create new account (APP_ID-OPENID)
- keycloak server return status NO_CONTENT(204) with a header "X-Redirect-Location"
- then client side can get all cookies and make progress to get access token