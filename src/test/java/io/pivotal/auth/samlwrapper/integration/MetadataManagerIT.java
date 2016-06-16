package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.samlwrapper.SamlWebSecurityConfigurerAdapter;
import io.pivotal.auth.samlwrapper.SamlWrapperApplication;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest({"saml.identity-provider-uris[0]=/okta.xml","saml.identity-provider-uris[1]=/okta.xml"})
public class MetadataManagerIT {

    @Autowired
    private SamlWebSecurityConfigurerAdapter adapter;

    @Test
    @DirtiesContext
    public void testMultipleIdentityProviders() throws Exception {
        MetadataManager metadata = adapter.metadata();

        List<MetadataProvider> providers = metadata.getProviders();

        // An additional provider is added by the MetadataGenerator, hence this is one more than
        // the number passed by the config.
        assertThat(providers.size(), Matchers.equalTo(2+1));
    }

}
