package io.pivotal.auth.samlwrapper;

import io.pivotal.auth.samlwrapper.config.SAMLConfiguration;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.test.util.ReflectionTestUtils;

import static org.hamcrest.MatcherAssert.assertThat;

public class SamlWebSecurityConfigurerAdapterTest {

    @Test
    public void testDefaultMaxAuthenticationAge() throws Exception {

        SAMLConfiguration config = new SAMLConfiguration();

        SamlWebSecurityConfigurerAdapter adapter = new SamlWebSecurityConfigurerAdapter();
        ReflectionTestUtils.setField(adapter, "samlConfiguration", config);
        WebSSOProfileConsumerImpl testWebSSOProfileConsumer = (WebSSOProfileConsumerImpl) adapter.webSSOProfileConsumer();
        assertThat(testWebSSOProfileConsumer.getMaxAuthenticationAge(), Matchers.equalTo(86400L));

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
}
