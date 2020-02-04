package org.vaadin.paul.spring.ui.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinServletRequest;
import io.tokenchannel.exceptions.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vaadin.paul.spring.app.security.ChallengeCreatedException;
import org.vaadin.paul.spring.app.security.CustomRequestCache;
import org.vaadin.paul.spring.app.security.SecondStepAuthenticationDetails;

@Route(value = LoginView.ROUTE)
@PageTitle("Login")
public class LoginView extends VerticalLayout {

    public static final String ROUTE = "login";
    private final TextField usernameTextField = new TextField();
    private final PasswordField passwordTextField = new PasswordField();
    private final TextField otpTokenTextField = new TextField();

    private final Button submitButton = new Button("Login");

    /**
     * Holder of the requestId
     */
    private String challengeId;

    public LoginView(final AuthenticationManager authenticationManager,
                     final CustomRequestCache requestCache) {

        usernameTextField.setLabel("Dime tu id");
        passwordTextField.setLabel("Contraseña");
        otpTokenTextField.setLabel("OTP Token");
        otpTokenTextField.setVisible(false);

        submitButton.addClickListener(buttonClickEvent -> {

            try {
                // try to authenticate with given credentials, should always return not null or throw an {@link AuthenticationException}
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(usernameTextField.getValue(),
                                passwordTextField.getValue());
                authenticationToken.setDetails(
                        new SecondStepAuthenticationDetails(this.challengeId, otpTokenTextField.getValue()));
                final Authentication authentication = authenticationManager
                        .authenticate(authenticationToken);
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
        this.add(usernameTextField);
        this.add(passwordTextField);
        this.add(otpTokenTextField);
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
            this.passwordTextField.setValue("");
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
            this.otpTokenTextField.setValue("");
        } else if (tce instanceof ChallengeClosedException ||
                tce instanceof MaxAttemptsExceededException || tce instanceof ChallengeExpiredException) {
            message = "Challenge closed. ";
            this.cleanChallenge();
        } else if (tce instanceof ChallengeNotFoundException) {
            // Hiding user does not exist
            message = "Bad Credentials";
            this.cleanChallenge();
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
        this.usernameTextField.setEnabled(false);
        this.passwordTextField.setEnabled(false);
        this.otpTokenTextField.setVisible(true);
    }

    private void cleanChallenge() {
        this.challengeId = "";
        this.usernameTextField.setValue("");
        this.passwordTextField.setValue("");
        this.otpTokenTextField.setValue("");
        this.usernameTextField.setEnabled(true);
        this.passwordTextField.setEnabled(true);
        this.otpTokenTextField.setVisible(false);
    }

    private void showErrorMessage(String message) {
        Notification.show(message, 2000, Notification.Position.MIDDLE).addThemeVariants(NotificationVariant.LUMO_ERROR);
    }
}
