package io.pivotal.auth.samlwrapper.integration;

import io.pivotal.auth.samlwrapper.SamlWrapperApplication;
import io.pivotal.auth.samlwrapper.pages.*;
import org.fluentlenium.adapter.FluentTest;
import org.junit.After;
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

import static org.fluentlenium.assertj.FluentLeniumAssertions.assertThat;

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
//		return new HtmlUnitDriver(true);
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
		assertThat(homePage).isAt();
	}

	@Test
	public void testErrorPageUnauthenticated() throws Exception {
		goTo(errorPage);
		assertThat(errorPage).isAt();
	}

	@Test
	public void testUnauthenticatedRedirect() throws Exception {
		goTo(authRequiredPage);
		assertThat(authRequiredPage);
		assertThat(oktaLoginPage).isAt();
	}

	@Test
	public void testLoginInFromOkta() throws Exception {
		goTo(oktaLoginPage);
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		assertThat(authRequiredPage).isAt();
	}

	@Test
	public void testLoginInFromApp() throws Exception {
		goTo(authRequiredPage);
		assertThat(oktaLoginPage).isAt();
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		assertThat(authRequiredPage).isAt();
	}

	@Test
	public void testSessionPersists() throws Exception {
		goTo(authRequiredPage);
		assertThat(oktaLoginPage).isAt();
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		assertThat(authRequiredPage).isAt();
		goTo(homePage);
		goTo(OKTA_LOGOUT_URL);
		goTo(authRequiredPage);
		assertThat(authRequiredPage).isAt();
	}

	@Test
	public void testLogout() throws Exception {
		goTo(authRequiredPage);
		assertThat(oktaLoginPage).isAt();
		oktaLoginPage.performLogin(TEST_USERNAME, TEST_PASSWORD);
		assertThat(authRequiredPage).isAt();
		goTo(logoutPage);
		goTo(OKTA_LOGOUT_URL);
		goTo(authRequiredPage);
		assertThat(oktaLoginPage).isAt();
	}

	// NJT notes:
	// Further tests (beyond scope? testing wrong thing?):
	// Failed log-in directs to correct error page,

	@After
	public void showDebugInformation() { // TODO: temporary debugging
		System.out.println("final URL: " + url());
		System.out.println("source:\n" + pageSource());
	}

}
