package io.pivotal.auth.samlwrapper.pages;

public class LogoutPage extends BasePage {

    public LogoutPage(Integer port) {
        super(port);
    }

    @Override
    public String getUrl() {
        return getBaseUrl() + "/saml/logout?local=true";
    }

}
