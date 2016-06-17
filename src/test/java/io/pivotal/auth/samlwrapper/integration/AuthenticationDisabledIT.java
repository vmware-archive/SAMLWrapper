package io.pivotal.auth.samlwrapper.integration;


import io.pivotal.auth.samlwrapper.pages.AuthRequiredPage;
import io.pivotal.auth.samlwrapper.pages.HomePage;
import io.pivotal.auth.testapp.SamlWrapperApplication;
import org.fluentlenium.adapter.FluentTest;
import org.fluentlenium.assertj.FluentLeniumAssertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.concurrent.TimeUnit;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest({"saml.authentication-disabled=true"})
public class AuthenticationDisabledIT extends FluentTest {

    private HomePage homePage;
    private AuthRequiredPage authRequiredPage;

    private int port = 8080;

    protected int getPort() {
        return port;
    }

    @Override
    public WebDriver getDefaultDriver() {
//        return new HtmlUnitDriver(true);
        return new FirefoxDriver();
    }

    @Before
    public void enableImplicitWaits() {
        getDriver().manage().timeouts().implicitlyWait(2, TimeUnit.SECONDS);
    }

    @Before
    public void generatePages() {
        homePage = createPage(HomePage.class, getPort());
        authRequiredPage = createPage(AuthRequiredPage.class, getPort());
    }


    @Test
    @DirtiesContext
    public void testAuthenticatedPagesAccessible() throws Exception {
//        goTo(homePage);
//        FluentLeniumAssertions.assertThat(homePage).isAt();
        goTo(authRequiredPage);
        FluentLeniumAssertions.assertThat(authRequiredPage).isAt();
    }
}
