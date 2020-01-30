package org.vaadin.paul.spring.ui.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import io.tokenchannel.exceptions.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.vaadin.paul.spring.app.security.ChallengeCreatedException;
import org.vaadin.paul.spring.app.security.CustomRequestCache;

@Route(value = LoginView.ROUTE)
@PageTitle("Login")
public class LoginView extends VerticalLayout {

    public static final String ROUTE = "login";
    private final TextField identifierTextField = new TextField();
    private final TextField authCodeTextField = new TextField();
    private final Button submitButton = new Button("Login");

    /**
     * Holder of the requestId
     */
    private String challengeId;

    public LoginView(final AuthenticationManager authenticationManager,
                     final CustomRequestCache requestCache) {

        identifierTextField.setLabel("Dime tu id");
        authCodeTextField.setPlaceholder("Validation Code");
        authCodeTextField.setVisible(false);

        submitButton.addClickListener(buttonClickEvent -> {

            try {
                // try to authenticate with given credentials, should always return not null or throw an {@link AuthenticationException}
                String identifier = StringUtils.hasText(this.challengeId) ? challengeId : identifierTextField.getValue();
                final Authentication authentication = authenticationManager
                        .authenticate(new UsernamePasswordAuthenticationToken(identifier, authCodeTextField.getValue()));

                // if authentication was successful we will update the security context and redirect to the page requested first
                SecurityContextHolder.getContext().setAuthentication(authentication);
                UI.getCurrent().navigate(requestCache.resolveRedirectUrl());
            } catch (AuthenticationException ae) {
                this.handleAuthenticationException((AuthenticationException) ae);
            } catch (Throwable ex) {
                this.showErrorMessage("Unexpected Error");
            }
        });

        this.setAlignItems(Alignment.CENTER);
        this.add(identifierTextField);
        this.add(authCodeTextField);
        this.add(submitButton);
    }

    private void handleAuthenticationException(AuthenticationException ae) {
        if (ae instanceof ChallengeCreatedException) {
            this.handleChallengeCreated(((ChallengeCreatedException) ae).getRequestId());
        } else if (ae.getCause() instanceof TokenChannelException) {
            this.handleTokenChannelException((TokenChannelException) ae.getCause());
        } else {
            this.showErrorMessage(ae.getLocalizedMessage());
        }
    }

    private void handleTokenChannelException(TokenChannelException tce) {
        String message;
        if (tce instanceof InvalidIdentifierException) {
            message = "Invalid Identifier";
            this.authCodeTextField.setValue("");
        } else if (tce instanceof OutOfBalanceException) {
            // Programatically notify app admin
            message = "Call support";
            this.cleanChallenge();
        } else if (tce instanceof TargetOptOutException) {
            // Programatically notify app admin
            message = "You opted out this service. You should use an alternative method";
            this.cleanChallenge();
        } else if (tce instanceof InvalidCodeException) {
            message = "Invalid code. Try again!";
            this.authCodeTextField.setValue("");
        } else if (tce instanceof ChallengeClosedException ||
                tce instanceof MaxAttemptsExceededException || tce instanceof ChallengeExpiredException) {
            message = "Challenge closed. ";
            this.cleanChallenge();
        } else if (tce instanceof ChallengeNotFoundException) {
            // Hiding user does not exist
            message = "Bad Credentials";
            this.authCodeTextField.setValue("");
        } else {
            if (tce instanceof BadRequestException) {
                System.out.println(String.format("BadRequest:  %s", ((BadRequestException) tce).getErrorInfo().toString()));
            }
            message = "Unable to process.Try again later";
            this.cleanChallenge();
        }
        this.showErrorMessage(message);
    }

    private void handleChallengeCreated(String requestId) {
        this.challengeId = requestId;
        this.identifierTextField.setEnabled(false);
        this.authCodeTextField.setValue("");
        this.authCodeTextField.setVisible(true);
    }

    private void cleanChallenge() {
        this.challengeId = "";
        this.identifierTextField.setValue("");
        this.authCodeTextField.setValue("");
        this.identifierTextField.setEnabled(true);
        this.authCodeTextField.setVisible(false);
    }

    private void showErrorMessage(String message) {
        Notification.show(message, 2000, Notification.Position.MIDDLE).addThemeVariants(NotificationVariant.LUMO_ERROR);
    }
}
