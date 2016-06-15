package io.pivotal.auth.samlwrapper.pages;

import org.openqa.selenium.By;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class HomePage extends BasePage {

    public HomePage(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/";
    }

    @Override
    public void isAt() {
        assertThat(find(By.className("home-page")), hasSize(1));
    }

}
