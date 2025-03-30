package Marcelina.example.TaskXcel.config;

import Marcelina.example.TaskXcel.security.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailServiceImpl userDetailService;
    private static final String[] permittedEndpoints = {"/logIn","/logIn?error", "/users/create", "/css/**", "/images/**", "/error/**"};

    public SecurityConfig(UserDetailServiceImpl userDetailService) {
        this.userDetailService = userDetailService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(permittedEndpoints).permitAll()
                        .requestMatchers("/users/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .userDetailsService(userDetailService)
                .authenticationManager(authenticationManager(http))
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);
        return http.build();
    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/logIn","/logIn?error").permitAll()
//                        .requestMatchers("/dashboard").hasAuthority("MANAGER")
//                        .requestMatchers("/tasks/**").hasAnyAuthority("EMPLOYEE", "MANAGER")
//                        .requestMatchers("/users/**").hasAuthority("ADMIN")
//                        .anyRequest().authenticated()
//                )
//                .formLogin(login -> login
//                        .loginPage("/logIn")
//                        .defaultSuccessUrl("/dashboard", true)
//                        .permitAll()
//                );
//
//        return http.build();
//    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailService).passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder.build();
    }

}
