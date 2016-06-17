package io.pivotal.auth.samlwrapper;

import io.pivotal.auth.samlwrapper.config.SAMLConfiguration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.util.*;

@Configuration
@EnableWebSecurity
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SamlWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    // This is for app-specific mapping from SAML data into a user (we can check permissions, etc. here). It is
    // provided explicitly to the SAMLAuthenticationProvider
    @Autowired
    private SAMLUserDetailsService samlUserDetailsService;

    @Autowired
    private SAMLConfiguration samlConfiguration;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // For testing allow all pages to be accessed without authentication.
        if( samlConfiguration.isAuthenticationDisabled() ) {
            http.authorizeRequests().anyRequest().permitAll();
        } else {
            http.httpBasic().authenticationEntryPoint(samlEntryPoint());

            // Disable Cross-Site-Request-Forgery checking for the SSO URLs (since they must accept data sent from the
            // Identity Provider's domains)
            http.csrf().ignoringAntMatchers(
                    samlConfiguration.getSsoUrl(),
                    samlConfiguration.getHokSsoUrl(),
                    samlConfiguration.getSingleLogoutUrl()
            );

            for (String url : samlConfiguration.getAllowUnauthenticatedAccessUrls()) {
                http.authorizeRequests().antMatchers(url).permitAll();
            }

            // ...and the URLs necessary for SSO
            http.authorizeRequests()
                    .antMatchers(samlConfiguration.getErrorUrl()).permitAll()
                    .antMatchers(samlConfiguration.getLogoutUrl()).permitAll()
                    .antMatchers(samlConfiguration.getSingleLogoutUrl()).permitAll()
                    .antMatchers(samlConfiguration.getSsoUrl()).permitAll()
                    .antMatchers(samlConfiguration.getHokSsoUrl()).permitAll()
                    .anyRequest().authenticated();
        }

    }

    // Use our SAML configuration for security
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
    }

    // Initialization of OpenSAML library
    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new SAMLBootstrap();
    }

    // This is the base configuration for the SAML authentication. We explicitly give it our app-specific user mapping
    // bean, and it auto-wires:
    //  SAMLLogger
    //  WebSSOProfileConsumer ["webSSOprofileConsumer"]
    //  WebSSOProfileConsumer ["hokWebSSOprofileConsumer"]
    // We explicitly register it during configure() and it must be a bean
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        provider.setUserDetails(samlUserDetailsService);
        provider.setForcePrincipalAsString(false);
        return provider;
    }

    // This is autowired by the SAMLAuthenticationProvider and configures the logging for SAML messages.
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    // This is autowired by the SAMLAuthenticationProvider and configures the SAML 2.0 WebSSO Assertion Consumer.
    @Bean(name = "webSSOprofileConsumer")
    public WebSSOProfileConsumer webSSOProfileConsumer() {
        WebSSOProfileConsumerImpl webSSOProfileConsumer = new WebSSOProfileConsumerImpl();
        webSSOProfileConsumer.setMaxAuthenticationAge(samlConfiguration.getMaxAuthAgeSeconds());
        return webSSOProfileConsumer;
    }

    // This is autowired by the SAMLAuthenticationProvider and configures the SAML 2.0 Holder-of-Key WebSSO Assertion
    // Consumer (which is an optional extra layer of security which Identity Providers can support).
    @Bean(name = "hokWebSSOprofileConsumer")
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // Optionally (not-so-optionally) auto-wired by WebSSOProfile
    @Bean
    public SAMLProcessor processor() {
        return new SAMLProcessorImpl(Arrays.asList(
                new HTTPRedirectDeflateBinding(parserPool()),
                new HTTPPostBinding(parserPool(), VelocityFactory.getEngine()), // REQUIRED for XML templating
                new HTTPSOAP11Binding(parserPool())
        ));
    }

    // This is used during OpenSAML parsing; it is provided explicitly in several places and consumed implicitly by
    // some internal parts of the library (so must be a bean). It provides an XML parser pool.
    @Bean(initMethod = "initialize") // TODO: possibly removable
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    // This registers all the Identity Providers which we trust. Auto-wired by WebSSOProfile.
    @Bean
    public MetadataManager metadata() throws MetadataProviderException, ResourceException {
        List<String> identityProviders = Arrays.asList(samlConfiguration.getIdentityProviderUris());

        List<MetadataProvider> providers = new ArrayList<>();
        for( String metaURI : identityProviders) {
            MetadataProvider metadataProvider = getMetadataProvider(metaURI);
            ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadata());
            extendedMetadataDelegate.setMetadataTrustCheck(true);
            extendedMetadataDelegate.setMetadataRequireSignature(false);
            providers.add(extendedMetadataDelegate);
        }

        return new CachingMetadataManager(providers);
    }

    public MetadataProvider getMetadataProvider(String metaURI) throws ResourceException, MetadataProviderException {
        Resource resource = new ClasspathResource(metaURI);
        ResourceBackedMetadataProvider metadataProvider = new ResourceBackedMetadataProvider(new Timer(true), resource);
        metadataProvider.setParserPool(parserPool());
        return metadataProvider;
    }

    // Setup advanced info about metadata
    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setSignMetadata(false);
        return extendedMetadata;
    }

    // This is our app key manager. It holds the key for signing SAML messages for security. It is important that the
    // keystore (samlKeystore.jks in this example) is unique to the app. New keystores can be generated using:
    //  keytool -genkey -keyalg RSA -alias selfsigned -keystore keystoreIT.jks -storepass changeit -validity 360 -keysize 2048
    @Bean
    public KeyManager keyManager() {

        SAMLConfiguration.KeyStoreConfig keyStoreConfig = samlConfiguration.getKeystore();

        return new JKSKeyManager(
                new DefaultResourceLoader().getResource(keyStoreConfig.getKeyStoreUri()),
                keyStoreConfig.getKeyStorePassword(),
                keyStoreConfig.getPasswordMap(),
                keyStoreConfig.getDefaultKey());
    }

    // This filter/endpoint handles triggering a login request. It is explicitly provided to the authentication system,
    // and its actual endpoint is not used (TODO: optimisation possible here?)
    // It auto-wires:
    //  WebSSOProfile [webSSOprofile]
    //  WebSSOProfile [ecpprofile] (TODO: not required? provided elsewhere?)
    //  WebSSOProfile [hokWebSSOProfile] (TODO: not required? provided elsewhere?)
    //  SAMLLogger
    //  SAMLDiscovery (optional)
    //  SAMLContextProvider
    //  MetadataManager
    @Bean
    @Order(0) // ensure auth is checked early in the filter chain
    public SAMLEntryPoint samlEntryPoint() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);

        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        return samlEntryPoint;
    }

    // This is autowired by SAMLEntryPoint TODO: what does it do? SAML 2.0 Web SSO profile
    // Auto-wires:
    //  MetadataManager
    //  SAMLProcessor (optional)
    @Bean(name = "webSSOprofile")
    public WebSSOProfile webSSOProfile() {
        return new WebSSOProfileImpl();
    }

    // This is auto-wired by SAMLEntryPoint TODO: what does it do? Provider of default SAML Context
    // This auto-wires:
    //  MetadataManager
    //  KeyManager
    //  SAMLMessageStorageFactory (optional)
    @Bean
    public SAMLContextProvider contextProvider() {
        return new SAMLContextProviderImpl();
    }

    // This bean ensures all the SAML metadata (for our Service Provider[s]) is ready for use. This method includes
    // some cut-down logic from MetadataGeneratorFilter (which has been removed entirely here). MetadataGeneratorFilter
    // allows the base URL to be determined at runtime by waiting for the first user request before generating the
    // metadata, but this will fail if behind a reverse proxy - it is better to provide the URL explicitly, in which
    // case MetadataGeneratorFilter is just unnecessary overhead.
    // This is auto-wired by SAMLContextProviderImpl
    @Bean
    public MetadataGenerator metadataGenerator() throws Exception {
        MetadataGenerator generator = new MetadataGenerator();
        generator.setEntityBaseURL(samlConfiguration.getEntityBaseUrl());
        generator.setEntityId(samlConfiguration.getEntityId());
        generator.setExtendedMetadata(extendedMetadata());
        generator.setIncludeDiscoveryExtension(false);
        generator.setKeyManager(keyManager());

        generator.setSamlEntryPoint(samlEntryPoint());
        generator.setSamlLogoutProcessingFilter(samlLogoutProcessingFilter());
        generator.setSamlWebSSOFilter(samlWebSSOProcessingFilter());
        generator.setSamlWebSSOHoKFilter(samlWebSSOHoKProcessingFilter());

        EntityDescriptor descriptor = generator.generateMetadata();
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
        memoryProvider.initialize();
        MetadataManager manager = metadata();
        manager.addMetadataProvider(new ExtendedMetadataDelegate(memoryProvider, generator.generateExtendedMetadata()));
        manager.setHostedSPName(descriptor.getEntityID());
        manager.refreshMetadata();

        return generator;
    }

    // This filter/endpoint handles Holder-of-Keys signin responses. These can be triggered by the user successfully
    // logging in, or by the user following a link configured inside their SSO provider. Whether this or
    // samlWebSSOProcessingFilter is used will depend on whether the Identity Provider uses HoK or not. The endpoint
    // gets form data submitted to it by the Identity Provider (from the user's browser) during the login process.
    @Bean
    @Order(0) // ensure auth is checked early in the filter chain
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter filter = new SAMLWebSSOHoKProcessingFilter();
        filter.setAuthenticationManager(authenticationManager()); // This takes samlAuthenticationProvider via configure below
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setFilterProcessesUrl(samlConfiguration.getHokSsoUrl());
        return filter;
    }

    // This filter/endpoint handles non-Holder-of-Keys signin responses. These can be triggered by the user
    // successfully logging in, or by the user following a link configured inside their SSO provider. The endpoint
    // gets form data submitted to it by the Identity Provider (from the user's browser) during the login process.
    @Bean
    @Order(0) // ensure auth is checked early in the filter chain
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setAuthenticationManager(authenticationManager()); // This takes samlAuthenticationProvider via configure below
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        filter.setFilterProcessesUrl(samlConfiguration.getSsoUrl());
        return filter;
    }

    // This filter/endpoint is triggered by the Identity Provider when they need to log the user out of all locations
    // ("single sign-out"). It will be called from the user's browser.
    @Bean
    @Order(0) // ensure auth is checked early in the filter chain
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        SAMLLogoutProcessingFilter filter = new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
        filter.setFilterProcessesUrl(samlConfiguration.getSingleLogoutUrl());
        return filter;
    }

    // Used by the SAMLLogoutProcessingFilter.
    @Bean
    public SingleLogoutProfile logoutProfile() {
        return new SingleLogoutProfileImpl();
    }

    // This is the handler used when logout is successful. We use it to redirect the user to a logged-out page.
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl(samlConfiguration.getLogoutRedirectUrl());
        return successLogoutHandler;
    }

    // This is for terminating our local session. It is invoked when the user logs out. We provide it explicitly to
    // the logout handlers, and it must be a bean TODO: what auto-wires this?
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    // This is the handler used when authentication is successful. We use it to redirect the user to a default
    // logged-in page if the SAML didn't include a token pointing to a specific page.
    @Bean
    public AuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl(samlConfiguration.getLoginRedirectUrl());
        return successRedirectHandler;
    }

    // This is the handler used when authentication fails. We use it to redirect the user to a configured failure page.
    // Note that typically a credential failure will be handled by the Identity Provider so will not reach this point;
    // the errors which are caught here include:
    //   user initially logged in too long ago (max-auth-age-seconds)
    //   internal errors with SAML messages (e.g. signed with unexpected key)
    //   TODO: are there others?
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl(samlConfiguration.getErrorUrl());
        return failureHandler;
    }

    // This filter/endpoint is called by the user (public endpoint) when they want to log out.
    @Bean
    @Order(0) // ensure auth is checked early in the filter chain
    public SAMLLogoutFilter samlLogoutFilter() {
        SAMLLogoutFilter filter = new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},  // local logout (just this app)
                new LogoutHandler[]{logoutHandler()}); // global logout (trigger for all apps - not supported)
        filter.setFilterProcessesUrl(samlConfiguration.getLogoutUrl());
        return filter;
    }

}
