package org.vaadin.paul.spring.app.security;


import io.tokenchannel.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import java.util.UUID;

public class TokenChannelPasswordlessAuthenticationProvider implements AuthenticationProvider {

    private final TokenChannel tokenChannel;

    private final ChannelType channel;
    private final String language;

    private final UserDetailsService userDetailsService;

    public TokenChannelPasswordlessAuthenticationProvider(TokenChannel tokenChannel, String language, ChannelType channelType,
                                                          UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService; // (1)

        this.tokenChannel = tokenChannel; // (2)
        this.language = language; // (3)
        this.channel = channelType; // (4)
    }

    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        if (authentication.getPrincipal() == null || !StringUtils.hasText(authentication.getName())) { // (5)
            throw new BadCredentialsException("Bad credentials");
        }

        if (this.isCreateChallengeRequest(authentication)) { // (6)

                this.createChallenge(authentication); // (7)
            throw new IllegalStateException("This block of code should be unreachable");
        } else {
            return this.verifyChallenge(authentication); // (8)
        }
    }

    private boolean isCreateChallengeRequest(Authentication authentication) throws AuthenticationException {
        return authentication.getCredentials() == null || !StringUtils.hasText(authentication.getCredentials().toString());
    }

    private void createChallenge(Authentication authentication) {

        try {

            final String identifier = authentication.getName(); // (9)
            UserDetails user = this.userDetailsService.loadUserByUsername(identifier);

            ChallengeResponse response = this.tokenChannel.challenge(this.channel, identifier, ChallengeOptions.builder()
                    .language(language)
                    .build()); // (10)
            throw new ChallengeCreatedException(response.getRequestId()); // (11)
        } catch (UsernameNotFoundException e) {
            throw new ChallengeCreatedException(UUID.randomUUID().toString());  // (12)
        } catch (ChallengeCreatedException cce) { // (13)
            throw cce;
        } catch (Throwable t) { // (14)
            // TokenChannel exceptions will be the cause of an AuthenticationException
            throw new AuthenticationServiceException(t.getLocalizedMessage(), t);
        }
    }

    private Authentication verifyChallenge(Authentication authentication) throws AuthenticationException {

        String challengeId = authentication.getName();
        String validationCode = authentication.getCredentials().toString();

        try {

            AuthenticateResponse authenticateResponse = this.tokenChannel.authenticate(challengeId, validationCode);

            try {
                UserDetails user = this.userDetailsService.loadUserByUsername(authenticateResponse.getIdentifier()); // (15)
                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                        user, authentication.getCredentials(), user.getAuthorities());
                result.setDetails(authentication.getDetails());
                return result;
            } catch (UsernameNotFoundException e) {
                throw new BadCredentialsException(
                        "Bad credentials");
            }
        } catch (Throwable t) { // TokenChannel exceptions will be the cause of an AuthenticationException
            throw new AuthenticationServiceException(t.getLocalizedMessage(), t);
        }
    }

    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class
                .isAssignableFrom(authentication));
    }

    public ChannelType getChannel() {
        return channel;
    }
}
