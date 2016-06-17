package io.pivotal.auth.samlwrapper.pages;

import org.openqa.selenium.By;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class UnauthPage1 extends BasePage {

    public UnauthPage1(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/unauth1";
    }

    @Override
    public void isAt() {
        assertThat(find(By.className("unauth1-page")), hasSize(1));
    }

}
