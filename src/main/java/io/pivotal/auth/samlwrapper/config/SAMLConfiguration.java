package io.pivotal.auth.samlwrapper.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "saml")
public class SAMLConfiguration {
    private long maxAuthAgeSeconds = 86400;

    public long getMaxAuthAgeSeconds() {
        return maxAuthAgeSeconds;
    }

    public void setMaxAuthAgeSeconds(long maxAuthAgeSeconds) {
        this.maxAuthAgeSeconds = maxAuthAgeSeconds;
    }

}
