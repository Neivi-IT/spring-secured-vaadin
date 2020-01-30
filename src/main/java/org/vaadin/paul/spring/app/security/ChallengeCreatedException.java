package org.vaadin.paul.spring.app.security;

import org.springframework.security.core.AuthenticationException;

/**
 * Authentication is invalid yet, but a challenge has been created. It is a wrapper for the requestId of the
 * challenge create call.
 */
public class ChallengeCreatedException extends AuthenticationException {

    public ChallengeCreatedException(String requestId) {
        super(requestId);
    }

    public String getRequestId() {
        return super.getMessage();
    }
}
