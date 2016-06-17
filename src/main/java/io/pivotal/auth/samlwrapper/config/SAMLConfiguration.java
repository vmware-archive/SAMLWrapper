package io.pivotal.auth.samlwrapper.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "saml")
public class SAMLConfiguration {
    private long maxAuthAgeSeconds = 86400;

    private String ssoUrl = "/saml/SSO";
    private String hokSsoUrl = "/saml/HoKSSO";
    private String errorUrl = "/error";
    private String logoutUrl = "/saml/logout";
    private String singleLogoutUrl = "/saml/SingleLogout";
    private String loginRedirectUrl = "/";
    private String logoutRedirectUrl = "/";

    private String entityBaseUrl = "http://localhost:48080";
    private String entityId = "http://localhost:48080/saml/metadata";

    private String[] IdentityProviderUris = new String[]{"/okta.xml"};

    private String[] allowUnauthenticatedAccessUrls = new String[] {"/"};

    private KeyStoreConfig keystore = new KeyStoreConfig();

    public static class KeyStoreConfig {
        private String keyStoreUri = "classpath:/keystoreIT.jks";
        private String keyStorePassword = "keystore";
        private Map<String,String> passwordMap = new HashMap<>();
        private String defaultKey = "samltestkey";

        public KeyStoreConfig() {
            passwordMap.put("samltestkey","samltest");
        }

        public String getKeyStoreUri() {
            return keyStoreUri;
        }

        public void setKeyStoreUri(String keyStoreUri) {
            this.keyStoreUri = keyStoreUri;
        }

        public String getKeyStorePassword() {
            return keyStorePassword;
        }

        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        public Map<String, String> getPasswordMap() {
            return passwordMap;
        }

        public void setPasswordMap(Map<String, String> passwordMap) {
            this.passwordMap = passwordMap;
        }

        public String getDefaultKey() {
            return defaultKey;
        }

        public void setDefaultKey(String defaultKey) {
            this.defaultKey = defaultKey;
        }

    }

    public long getMaxAuthAgeSeconds() {
        return maxAuthAgeSeconds;
    }

    public void setMaxAuthAgeSeconds(long maxAuthAgeSeconds) {
        this.maxAuthAgeSeconds = maxAuthAgeSeconds;
    }

    public String getSsoUrl() {
        return ssoUrl;
    }

    public void setSsoUrl(String ssoUrl) {
        this.ssoUrl = ssoUrl;
    }

    public String getHokSsoUrl() {
        return hokSsoUrl;
    }

    public void setHokSsoUrl(String hokSsoUrl) {
        this.hokSsoUrl = hokSsoUrl;
    }

    public String getErrorUrl() {
        return errorUrl;
    }

    public void setErrorUrl(String errorUrl) {
        this.errorUrl = errorUrl;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public String getSingleLogoutUrl() {
        return singleLogoutUrl;
    }

    public void setSingleLogoutUrl(String singleLogoutUrl) {
        this.singleLogoutUrl = singleLogoutUrl;
    }

    public String getLogoutRedirectUrl() {
        return logoutRedirectUrl;
    }

    public void setLogoutRedirectUrl(String logoutRedirectUrl) {
        this.logoutRedirectUrl = logoutRedirectUrl;
    }

    public String getLoginRedirectUrl() {
        return loginRedirectUrl;
    }

    public void setLoginRedirectUrl(String loginRedirectUrl) {
        this.loginRedirectUrl = loginRedirectUrl;
    }

    public String getEntityBaseUrl() {
        return entityBaseUrl;
    }

    public void setEntityBaseUrl(String entityBaseUrl) {
        this.entityBaseUrl = entityBaseUrl;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String[] getIdentityProviderUris() {
        return IdentityProviderUris;
    }

    public void setIdentityProviderUris(String[] identityProviderUris) {
        IdentityProviderUris = identityProviderUris;
    }

    public KeyStoreConfig getKeystore() {
        return keystore;
    }

    public void setKeystore(KeyStoreConfig keystore) {
        this.keystore = keystore;
    }

    public String[] getAllowUnauthenticatedAccessUrls() {
        return allowUnauthenticatedAccessUrls;
    }

    public void setAllowUnauthenticatedAccessUrls(String[] allowUnauthenticatedAccessUrls) {
        this.allowUnauthenticatedAccessUrls = allowUnauthenticatedAccessUrls;
    }
}
