package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.config;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.PtaiUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.config.AuthorizationServerConfig.REALM;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private PtaiUserDetailsService ptaiUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(ptaiUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    @Order(Ordered.HIGHEST_PRECEDENCE)
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable()
                .authorizeRequests()
                // What to protect
                //
                // Protect only API
                .antMatchers("/api/diagnostic/**", "/api/sast/**", "/api/admin/**").authenticated()
                .antMatchers("/api/public/**").permitAll()
                .anyRequest().permitAll()
                // .antMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources/**", "/configuration/security", "/swagger-ui.html", "/webjars/**", "/csrf", "/").permitAll()
                // .antMatchers("/public/**").permitAll()
                // .antMatchers("/actuator/**").permitAll()
                // .antMatchers("/oauth/token").permitAll()
                // .anyRequest().authenticated()
                .and()
                .httpBasic().realmName(REALM);
    }


    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
