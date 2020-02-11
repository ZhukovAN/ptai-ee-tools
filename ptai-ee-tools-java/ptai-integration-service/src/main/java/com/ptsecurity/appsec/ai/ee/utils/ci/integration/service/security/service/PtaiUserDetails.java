package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.Role;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.UserRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class PtaiUserDetails implements UserDetails {

    @Getter
    private Collection<? extends GrantedAuthority> authorities;

    @Getter
    private String password;

    @Getter
    private String username;

    public PtaiUserDetails(User user) {
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.authorities = translate(user.getRoles());
    }

    private Collection<? extends GrantedAuthority> translate(List<UserRole> userRoles) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (UserRole userRole : userRoles) {
            String name = userRole.getRole().getName().toUpperCase();
            if (!name.startsWith("ROLE_"))
                name = "ROLE_" + name;
            authorities.add(new SimpleGrantedAuthority(name));
        }
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
