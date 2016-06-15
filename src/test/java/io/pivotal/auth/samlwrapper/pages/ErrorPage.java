package io.pivotal.auth.samlwrapper.pages;

import org.openqa.selenium.By;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class ErrorPage extends BasePage {

    public ErrorPage(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/error";
    }

    @Override
    public void isAt() {
        assertThat(find(By.className("error-page")), hasSize(1));
    }

}
