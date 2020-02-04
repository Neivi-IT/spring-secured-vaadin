package org.vaadin.paul.spring.app.security;


import io.tokenchannel.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.UUID;

public class TokenChannel2FAAuthenticationProvider implements AuthenticationProvider {

    private final TokenChannel tokenChannel;

    private final ChannelType channel;
    private final String language;

    // Delegates username/password authentication
    private DaoAuthenticationProvider daoAuthenticationProvider;

    public TokenChannel2FAAuthenticationProvider(UserDetailsService userDetailsService,
                                                 PasswordEncoder passwordEncoder,
                                                 TokenChannel tokenChannel, String language,
                                                 ChannelType channelType) {

        this.tokenChannel = tokenChannel;
        this.language = language;
        this.channel = channelType;

        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        this.daoAuthenticationProvider = daoAuthenticationProvider; // (1)

    }

    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        authentication = this.daoAuthenticationProvider.authenticate(authentication); // (2)

        if (!authentication.isAuthenticated() || authentication.getPrincipal() == null || !(authentication.getPrincipal() instanceof User)) {
            throw new BadCredentialsException("Bad credentials");
        }

        if (this.isCreateChallengeRequest(authentication)) { // (3)

            this.createChallenge(authentication);
            throw new IllegalStateException("This block of code should be unreachable");
        } else {
            return this.verifyChallenge(authentication);
        }
    }

    private boolean isCreateChallengeRequest(Authentication authentication) throws AuthenticationException {
        SecondStepAuthenticationDetails details = (SecondStepAuthenticationDetails) authentication.getDetails();
        if (details == null || !StringUtils.hasText(details.getChallengeId()) || !StringUtils.hasText(details.getOtpToken())) {
            return true;
        }
        return false;
    }

    private void createChallenge(Authentication authentication) {

        try {

            User user = (User) authentication.getPrincipal(); // (4)
            String lang = StringUtils.hasText(user.getLanguage()) ? user.getLanguage() : this.language; // (5)

            ChallengeResponse response = this.tokenChannel.challenge(this.channel, user.getPhonenumber(), ChallengeOptions.builder()
                    .language(lang)
                    .build());
            throw new ChallengeCreatedException(response.getRequestId());
        } catch (UsernameNotFoundException e) {
            throw new ChallengeCreatedException(UUID.randomUUID().toString());
        } catch (ChallengeCreatedException cce) {
            throw cce;
        } catch (Throwable t) {
            // TokenChannel exceptions will be the cause of an AuthenticationException
            throw new AuthenticationServiceException(t.getLocalizedMessage(), t);
        }
    }

    private Authentication verifyChallenge(Authentication authentication) throws AuthenticationException {
        SecondStepAuthenticationDetails details = (SecondStepAuthenticationDetails) authentication.getDetails();

        String challengeId = details.getChallengeId(); // (6)
        String validationCode = details.getOtpToken();

        try {

            AuthenticateResponse authenticateResponse = this.tokenChannel.authenticate(challengeId, validationCode);
            return authentication;
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
