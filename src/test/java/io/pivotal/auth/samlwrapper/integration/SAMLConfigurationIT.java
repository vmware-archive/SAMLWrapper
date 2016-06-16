package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.samlwrapper.SamlWrapperApplication;
import io.pivotal.auth.samlwrapper.config.SAMLConfiguration;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest("saml.max-auth-age-seconds=70")
public class SAMLConfigurationIT {
    @Autowired
    private SAMLConfiguration config;

    @Test
    public void testConfigurationIsConfigurable() throws Exception {
        Assert.assertThat(config.getMaxAuthAgeSeconds(), Matchers.equalTo(70L));
    }
}
