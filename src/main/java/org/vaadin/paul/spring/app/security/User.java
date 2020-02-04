package org.vaadin.paul.spring.app.security;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
@Builder
public class User implements UserDetails {

    private String username;
    private String password;
    private boolean accountNonExpired;
    private boolean credentialsNonExpired;
    private boolean accountNonLocked;
    private boolean enabled;
    private Collection<? extends GrantedAuthority> authorities;

    private String phonenumber;
    private String language;

}
