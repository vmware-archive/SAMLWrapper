package io.pivotal.auth.samlwrapper.pages;

import org.fluentlenium.core.FluentPage;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class OktaLoginPage extends FluentPage {
    private final String url;

    public OktaLoginPage(String url) {
        this.url = url;
    }

    @Override public String getUrl() {
        return url;
    }

    @Override public void isAt() {
        assertThat(find(By.id("user-signin")), hasSize(1));
        assertThat(find(By.id("pass-signin")), hasSize(1));
    }

    private void dismissBrowserAlert() {
        try {
            getDriver().switchTo().alert().accept();
        } catch(NoAlertPresentException ex) {
            // Alert was not present; ignore
        }
    }

    public void performLogin(String username, String password) {
        findFirst(By.id("user-signin")).text(username);
        findFirst(By.id("pass-signin")).text(password);
        findFirst(By.id("signin-button")).click();

        // Some browsers (Firefox) may display a warning about submitting https data to a http URL. Dismiss this.
        dismissBrowserAlert();
    }
}
