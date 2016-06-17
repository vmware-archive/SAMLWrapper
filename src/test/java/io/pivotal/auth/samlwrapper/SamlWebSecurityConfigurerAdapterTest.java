package io.pivotal.auth.samlwrapper;

import io.pivotal.auth.samlwrapper.config.SAMLConfiguration;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;

public class SamlWebSecurityConfigurerAdapterTest {

    @Test
    public void testSAMLConfigurationDefaults() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        assertThat(config.getMaxAuthAgeSeconds(), Matchers.equalTo(86400L));
        assertThat(config.getSsoUrl(), Matchers.equalTo("/saml/SSO"));
        assertThat(config.getHokSsoUrl(), Matchers.equalTo("/saml/HoKSSO"));
        assertThat(config.getErrorUrl(), Matchers.equalTo("/error"));
        assertThat(config.getLogoutUrl(), Matchers.equalTo("/saml/logout"));
        assertThat(config.getSingleLogoutUrl(), Matchers.equalTo("/saml/SingleLogout"));
        assertThat(config.getLogoutRedirectUrl(), Matchers.equalTo("/"));
        assertThat(config.getLoginRedirectUrl(), Matchers.equalTo("/"));
        assertThat(config.getEntityBaseUrl(), Matchers.equalTo("http://localhost:48080"));
        assertThat(config.getEntityId(), Matchers.equalTo("http://localhost:48080/saml/metadata"));
        assertThat(config.getIdentityProviderUris(), Matchers.arrayContaining("/okta.xml"));
        assertThat(config.getIdentityProviderUris().length, Matchers.equalTo(1));
        assertThat(config.getAllowUnauthenticatedAccessUrls(), Matchers.arrayContaining("/"));
        assertThat(config.getAllowUnauthenticatedAccessUrls().length, Matchers.equalTo(1));


        SAMLConfiguration.KeyStoreConfig keyStore = config.getKeystore();

        assertThat(keyStore.getKeyStoreUri(), Matchers.equalTo("classpath:/keystoreIT.jks"));
        assertThat(keyStore.getKeyStorePassword(), Matchers.equalTo("keystore"));
        assertThat(keyStore.getPasswordMap(), Matchers.hasEntry("samltestkey", "samltest"));
        assertThat(keyStore.getPasswordMap().size(), Matchers.equalTo(1));
        assertThat(keyStore.getDefaultKey(), Matchers.equalTo("samltestkey"));

    }

    @Test
    public void testMaxAuthenticationAgeConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setMaxAuthAgeSeconds(10);

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);
        WebSSOProfileConsumerImpl testWebSSOProfileConsumer = (WebSSOProfileConsumerImpl) adapter.webSSOProfileConsumer();
        assertThat(testWebSSOProfileConsumer.getMaxAuthenticationAge(), Matchers.equalTo(10L));
    }

    @Test
    public void testSSOUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setSsoUrl("/test/SSO/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter() {
            @Override
            protected AuthenticationManager authenticationManager() {
                return null;
            }
        };
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SAMLProcessingFilter samlWebSSOProcessingFilter = adapter.samlWebSSOProcessingFilter();
        assertThat(samlWebSSOProcessingFilter.getFilterProcessesUrl(), Matchers.equalTo("/test/SSO/url"));
    }

    @Test
    public void testHokSSOUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setHokSsoUrl("/test/HoKSSO/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter() {
            @Override
            protected AuthenticationManager authenticationManager() {
                return null;
            }
        };
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = adapter.samlWebSSOHoKProcessingFilter();
        assertThat(samlWebSSOHoKProcessingFilter.getFilterProcessesUrl(), Matchers.equalTo("/test/HoKSSO/url"));

    }

    @Test
    public void testErrorUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setErrorUrl("/test/error/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SimpleUrlAuthenticationFailureHandler authenticationFailureHandler = adapter.authenticationFailureHandler();
        assertThat(ReflectionTestUtils.getField(authenticationFailureHandler, "defaultFailureUrl"), Matchers.equalTo("/test/error/url"));
    }

    @Test
    public void testLogoutUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setLogoutUrl("/test/logout/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SAMLLogoutFilter samlLogoutFilter = adapter.samlLogoutFilter();
        assertThat(samlLogoutFilter.getFilterProcessesUrl(), Matchers.equalTo("/test/logout/url"));
    }

    @Test
    public void testSingleLogoutUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setSingleLogoutUrl("/test/SingleLogout/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = adapter.samlLogoutProcessingFilter();
        assertThat(samlLogoutProcessingFilter.getFilterProcessesUrl(), Matchers.equalTo("/test/SingleLogout/url"));
    }

    @Test
    public void testLogoutRedirectUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setLogoutRedirectUrl("/test/LogoutRedirect/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SimpleUrlLogoutSuccessHandler successLogoutHandler = adapter.successLogoutHandler();
        assertThat(ReflectionTestUtils.getField(successLogoutHandler, "defaultTargetUrl"), Matchers.equalTo("/test/LogoutRedirect/url"));
    }

    @Test
    public void testLoginRedirectUrlConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setLoginRedirectUrl("/test/login/url");

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        AuthenticationSuccessHandler successRedirectHandler = adapter.successRedirectHandler();
        assertThat(ReflectionTestUtils.getField(successRedirectHandler, "defaultTargetUrl"), Matchers.equalTo("/test/login/url"));
    }

    @Test
    public void testIdentityProviderUriConfigurable() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();
        config.setIdentityProviderUris(new String[]{"/test/provider.xml"});

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        SamlWebSecurityConfigurerAdapter spiedAdapter = Mockito.spy(adapter);

        // When the getMetadataProvider method is invoked with our expected (fake) URI,
        // call it instead with a valid URI, so that construction can proceed.
        Mockito.doReturn(spiedAdapter.getMetadataProvider("/okta.xml"))
                .when(spiedAdapter).getMetadataProvider("/test/provider.xml");
        MetadataManager metadata = spiedAdapter.metadata();

        Mockito.verify(spiedAdapter).getMetadataProvider("/test/provider.xml");

    }

    @Test
    public void testKeyStoreConfigurable() throws Exception {
        SAMLConfiguration.KeyStoreConfig keyStoreConfig = new SAMLConfiguration.KeyStoreConfig();
        keyStoreConfig.setKeyStoreUri("classpath:/keystoreTest.jks");
        keyStoreConfig.setKeyStorePassword("password");
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put("testkey1", "password1");
        passwordMap.put("testkey2", "password2");
        keyStoreConfig.setPasswordMap(passwordMap);
        keyStoreConfig.setDefaultKey("testkey1");
        SAMLConfiguration config = new SAMLConfiguration();
        config.setKeystore(keyStoreConfig);

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);

        KeyManager keyManager = adapter.keyManager();
        /**
         * We are implicitly testing that our KeyStoreUri and password are correct as the correct keys are
         * contained in this store.
         * We cannot test retrieving passwords as these are encrypted.
         */
        assertThat(keyManager.getDefaultCredential().getEntityId(), Matchers.equalTo("testkey1"));
        assertThat(keyManager.getAvailableCredentials(), Matchers.containsInAnyOrder("testkey1", "testkey2"));
        assertThat(keyManager.getAvailableCredentials().size(), Matchers.equalTo(2));

    }


}
