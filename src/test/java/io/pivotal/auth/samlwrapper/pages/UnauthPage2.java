package io.pivotal.auth.samlwrapper.pages;

import org.openqa.selenium.By;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class UnauthPage2 extends BasePage {

    public UnauthPage2(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/unauth2";
    }

    @Override
    public void isAt() {
        assertThat(find(By.className("unauth2-page")), hasSize(1));
    }

}
