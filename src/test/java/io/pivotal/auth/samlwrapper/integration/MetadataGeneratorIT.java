package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.samlwrapper.SamlWebSecurityConfigurerAdapter;
import io.pivotal.auth.testapp.SamlWrapperApplication;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest({"saml.entity-base-url=/test/entity/url", "saml.entity-id=/test/entity-id"})
public class MetadataGeneratorIT {

    @Autowired
    private SamlWebSecurityConfigurerAdapter adapter;

    @Test
    @DirtiesContext
    public void testEntityBaseURL() throws Exception {
        MetadataGenerator generator = adapter.metadataGenerator();
        assertThat(generator.getEntityBaseURL(), Matchers.equalTo("/test/entity/url"));
    }

    @Test
    @DirtiesContext
    public void testEntityID() throws Exception {
        MetadataGenerator generator = adapter.metadataGenerator();
        assertThat(generator.getEntityId(), Matchers.equalTo("/test/entity-id"));
    }

}
