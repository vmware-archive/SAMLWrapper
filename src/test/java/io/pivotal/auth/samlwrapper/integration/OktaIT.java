package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.samlwrapper.SamlWrapperApplication;
import io.pivotal.auth.samlwrapper.pages.*;
import org.fluentlenium.adapter.FluentTest;
import org.fluentlenium.assertj.FluentLeniumAssertions;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = SamlWrapperApplication.class)
@WebIntegrationTest("server.port=" + OktaIT.PORT)
public class OktaIT extends FluentTest {

	/**
	 * Port number is configured inside Okta's app configuration, so can only be changed if the Okta app is also
	 * changed. 48080 chosen as an unlikely port number which is outside the ephemeral range.
	 */
	static final int PORT = 48080;

	private static final String OKTA_BASE_URL = "https://dev-904418.oktapreview.com/";
	private static final String OKTA_LOGIN_URL = OKTA_BASE_URL + "app/samlwrapperdev904418_samlwrappertest_1/exk6hqz3edkJMkkvW0h7/sso/saml";
	private static final String OKTA_LOGOUT_URL = OKTA_BASE_URL + "login/signout";
	private static final String TEST_USERNAME = "samlwrappertest+user@gmail.com";
	private static final String TEST_PASSWORD = "SeZ1fmjoyKSDB4quSEQriw6DY5X5zEk";

	@Value("${local.server.port}")
	private int port;

	private OktaLoginPage oktaLoginPage;
	private HomePage homePage;
	private ErrorPage errorPage;
	private AuthRequiredPage authRequiredPage;
	private LogoutPage logoutPage;

	protected int getPort() {
		return port;
	}

	@Override
	public WebDriver getDefaultDriver() {
//		return new HtmlUnitDriver(true); // Something inside the Okta login process is currently failing with this driver. TODO: investigate
        return new FirefoxDriver();
	}

	@Before
	public void enableImplicitWaits() {
		getDriver().manage().timeouts().implicitlyWait(2, TimeUnit.SECONDS);
	}

	@Before
	public void generatePages() {
		oktaLoginPage = createPage(OktaLoginPage.class, OKTA_LOGIN_URL);
		homePage = createPage(HomePage.class, getPort());
		errorPage = createPage(ErrorPage.class, getPort());
		authRequiredPage = createPage(AuthRequiredPage.class, getPort());
		logoutPage = createPage(LogoutPage.class, getPort());

	}

	@Test
	public void testUnauthenticatedAllowedPages() throws Exception {
		goTo(homePage);
		FluentLeniumAssertions.assertThat(homePage).isAt();
	}

	@Test
	public void testErrorPageUnauthenticated() throws Exception {
		goTo(errorPage);
		FluentLeniumAssertions.assertThat(errorPage).isAt();
	}

	@Test
	public void testUnauthenticatedRedirect() throws Exception {
		goTo(authRequiredPage);
		FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
	}

	@Test
	public void testLoginInFromOkta() throws Exception {
		goTo(oktaLoginPage);
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		FluentLeniumAssertions.assertThat(homePage).isAt();
	}

	@Test
	public void testLoginInFromApp() throws Exception {
		goTo(authRequiredPage);
		FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		FluentLeniumAssertions.assertThat(authRequiredPage).isAt();
	}

	private void loginFromApp() {
		goTo(authRequiredPage);
		FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		FluentLeniumAssertions.assertThat(authRequiredPage).isAt();
	}

	@Test
	public void testSessionPersists() throws Exception {
		loginFromApp();
		goTo(homePage);
		goTo(OKTA_LOGOUT_URL);
		goTo(authRequiredPage);
		FluentLeniumAssertions.assertThat(authRequiredPage).isAt();
	}

	@Test
	public void testLogout() throws Exception {
		loginFromApp();
		goTo(logoutPage);
		goTo(OKTA_LOGOUT_URL);
		goTo(authRequiredPage);
		FluentLeniumAssertions.assertThat(oktaLoginPage).isAt();
	}

	@Test
	public void testRejectInvalidLogins() throws Exception {
		goTo(homePage.getUrl()+"saml/SSO");
		FluentLeniumAssertions.assertThat(errorPage).isAt();
	}

	@Test
	public void testUsernameAppearsOnLogin() throws Exception {
		loginFromApp();
		assertThat(authRequiredPage.getUsernameTest(), Matchers.equalTo("Logged in as " + TEST_USERNAME + "."));
	}

}
