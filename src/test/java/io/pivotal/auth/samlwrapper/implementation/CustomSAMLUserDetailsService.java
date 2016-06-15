package io.pivotal.auth.samlwrapper.implementation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomSAMLUserDetailsService implements SAMLUserDetailsService {
    private static final Logger LOG = LoggerFactory.getLogger(CustomSAMLUserDetailsService.class);

    @Override
    public User loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        String userID = credential.getNameID().getValue();

        LOG.info(userID + " is logged in");
        List<GrantedAuthority> authorities = new ArrayList<>();

        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        return new User(userID, "", authorities);
    }
}
