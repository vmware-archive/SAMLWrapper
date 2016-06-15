package io.pivotal.auth.samlwrapper.pages;

import org.fluentlenium.core.FluentPage;

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.MatcherAssert.assertThat;

public class BasePage extends FluentPage {

    private final int port;

    public BasePage(Integer port) {
        this.port = port;
    }

    public String getBaseUrl() {
        return "http://localhost:" + port;
    }

    @Override
    public void isAt() {
        assertThat(url(), endsWith(getUrl()));
    }

}
