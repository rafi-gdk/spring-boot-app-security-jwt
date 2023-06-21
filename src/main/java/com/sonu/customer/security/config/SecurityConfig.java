package com.sonu.customer.security.config;

import com.sonu.customer.security.filter.AuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // we can restrict role based access in the controller
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    @Qualifier("delegatedAuthenticationEntryPoint")
    AuthenticationEntryPoint authEntryPoint;

    @Autowired
    private AuthenticationFilter authenticationFilter;


    @Bean
    public AuthenticationProvider authenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(encoder);
        return authenticationProvider;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .and()
                .cors()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers(antMatcher("/**/authenticate/**")).permitAll()
                .requestMatchers(antMatcher("/**/getCustomer/**")).permitAll()
                .requestMatchers(antMatcher("/**/getAllCustomers")).hasAuthority("admin")
                //.requestMatchers(antMatcher("/h2-console/**")).hasAuthority("ADMIN")
                //.and().csrf().ignoringAntMatchers("/h2-console/**")
                //.and().headers().frameOptions().disable()
                .and().authorizeHttpRequests().anyRequest().authenticated()
                .and()
                .authenticationProvider(authenticationProvider())
                .csrf().disable()
                .formLogin()
                .and()
                .httpBasic()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authEntryPoint)
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
