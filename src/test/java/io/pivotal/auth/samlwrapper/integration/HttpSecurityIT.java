package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.testapp.SamlWrapperApplication;
import io.pivotal.auth.samlwrapper.pages.*;
import org.fluentlenium.adapter.FluentTest;
import org.fluentlenium.assertj.FluentLeniumAssertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.concurrent.TimeUnit;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest({"saml.allow-unauthenticated-access-urls[0]=/unauth1","saml.allow-unauthenticated-access-urls[1]=/unauth2"})
public class HttpSecurityIT extends FluentTest {

    private static final String OKTA_BASE_URL = "https://dev-904418.oktapreview.com/";
    private static final String OKTA_LOGIN_URL = OKTA_BASE_URL + "app/samlwrapperdev904418_samlwrappertest_1/exk6hqz3edkJMkkvW0h7/sso/saml";

    private HomePage homePage;
    private UnauthPage1 unauth1Page;
    private UnauthPage2 unauth2Page;
    private OktaLoginPage oktaLoginPage;
    private AuthRequiredPage authRequiredPage;

    private int port = 8080;

    protected int getPort() {
        return port;
    }

    @Override
    public WebDriver getDefaultDriver() {
		return new HtmlUnitDriver(true);
//        return new FirefoxDriver();
    }

    @Before
    public void enableImplicitWaits() {
        getDriver().manage().timeouts().implicitlyWait(2, TimeUnit.SECONDS);
    }

    @Before
    public void generatePages() {
        homePage = createPage(HomePage.class, getPort());
        unauth1Page = createPage(UnauthPage1.class, getPort());
        unauth2Page = createPage(UnauthPage2.class, getPort());
        oktaLoginPage = createPage(OktaLoginPage.class, OKTA_LOGIN_URL);
        authRequiredPage = createPage(AuthRequiredPage.class, getPort());
    }

    @Test
    @DirtiesContext
    public void testUnauthenticatedPagesConfigurable() throws Exception {
        goTo(unauth1Page);
        FluentLeniumAssertions.assertThat(unauth1Page).isAt();
        goTo(unauth2Page);
        FluentLeniumAssertions.assertThat(unauth2Page).isAt();
    }

    @Test
    @DirtiesContext
    public void testAuthenticatedPagesInaccessible() throws Exception {
        goTo(homePage);
        FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
        goTo(authRequiredPage);
        FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
    }
}
