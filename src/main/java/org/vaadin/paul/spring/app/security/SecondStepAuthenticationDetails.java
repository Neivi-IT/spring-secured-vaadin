package org.vaadin.paul.spring.app.security;

import lombok.Getter;

@Getter
public class SecondStepAuthenticationDetails {

    private String otpToken;
    private String challengeId;

    public SecondStepAuthenticationDetails(String challengeId, String otpToken) {
        super();
        this.challengeId = challengeId;
        this.otpToken = otpToken;
    }
}

