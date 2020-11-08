package com.mhp.coding.challenges.auth.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
/*
    Eg. for Basic Auth
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Example User and Password Test -> could be loaded from DB
        auth.inMemoryAuthentication().withUser("admin").password("password").roles("ADMIN");
        auth.inMemoryAuthentication().withUser("user").password("password2").roles("USER");
    }
*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                // Second Method to Secure endpoints
                    //.antMatchers(HttpMethod.GET, "/v1/door").hasAnyRole("ADMIN", "USER")
                    //.antMatchers(HttpMethod.POST, "/v1/door").hasRole("ADMIN")
                .anyRequest().fullyAuthenticated()
                .and().httpBasic()
                .and().x509().subjectPrincipalRegex("CN=(.*?)(?:,|$)").userDetailsService(userDetailsService())
        .and().requiresChannel().anyRequest().requiresSecure();
    }

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                if (username.equals("Nils Luedeke")) {
                    return new User(username, "",
                            AuthorityUtils
                                    .commaSeparatedStringToAuthorityList("ROLE_USER"));
                } else if (username.equals("Nils Admin")) {
                    return new User(username, "",
                            AuthorityUtils
                                    .commaSeparatedStringToAuthorityList("ROLE_ADMIN"));

                }
                throw new UsernameNotFoundException("User not found!");
            }
        };
    }
}
