package io.pivotal.auth.samlwrapper.pages;

import org.openqa.selenium.By;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class AuthRequiredPage extends BasePage {

    public AuthRequiredPage(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/auth-required";
    }

    @Override
    public void isAt() {
        assertThat(find(By.className("auth-required")), hasSize(1));
    }

}
