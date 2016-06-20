SAMLWrapper

A basic library for adding SAML authentication to a webapp.

To include SAMLWrapper in your project;

1. Run 'mvn clean install' on the SAMLWrappper project to add to your local repository.
1. In your target project add the mavenLocal() repository to build.gradle.
1. Add 'io.pivotal.auth:samlwrapper:0.0.1-SNAPSHOT' to compile time dependencies. 
1. Create a CustomSAMLUserDetailsService class to handle getting user details (e.g. by copying from the test app).
1. Add the SAML metadata from your authentication provider to the resources of your project, and add the location to 'identity-provider-uris' in the application.yml file.
1. Create a keystore for your project and add this to application.yml e.g. using 'keytool -genkeypair -keyalg RSA -alias <my-project> -keystore <my-keystore.jks> -storepass <my-store-password> -validity 360 -keysize 2048'  
1. Fill in the URLs in application.yml - see below.

Example application.yml:

    saml:
      ssoUrl: /saml/sso
      hokSsoUrl: /saml/HoKSSO
      logoutUrl: /saml/logout
      singleLogoutUrl: /saml/SingleLogout
      errorUrl: /error
      loginRedirectUrl: /
      logoutRedirectUrl: /
    
      identity-provider-uris:
        - /saml.xml
    
      allow-unauthenticated-access-urls:
        - robots.txt
        - favicon.ico
    
      keystore:
        key-store-uri: classpath:/my-keystore.jks
        key-store-password: my-password
        password-map:
          my-project: my-password
        default-key: my-project