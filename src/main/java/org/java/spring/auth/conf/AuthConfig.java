package org.java.spring.auth.conf;

import org.java.spring.auth.services.UserServ;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthConfig {
	@Bean
	PasswordEncoder passwordEncoder() {
		
//	    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		
		return new BCryptPasswordEncoder();
	}
	
	@SuppressWarnings("deprecation")
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    
//		http.authorizeHttpRequests()
//		        .requestMatchers("/user").hasAuthority("USER")
//		        .requestMatchers("/admin").hasAuthority("ADMIN")
//		        .requestMatchers("/").permitAll()
//	        .and().formLogin()
//	        .and().logout();
//	    
//	    return http.build();
		return http.authorizeRequests(a->
				a.requestMatchers("/users/**").hasAnyAuthority("USER" , "ADMIN")
				.requestMatchers("/admin/**").hasAuthority("ADMIN")
				.requestMatchers("/**").permitAll())
				.formLogin(f->f.permitAll()).logout(l->l.logoutSuccessUrl("/")).build();
	}
	
	@Bean
	UserDetailsService userDetailsService() {
	    return new UserServ();
	}
	
	@Bean
	DaoAuthenticationProvider authenticationProvider() {
	
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	 
	    authProvider.setUserDetailsService(userDetailsService());
	    authProvider.setPasswordEncoder(passwordEncoder());
	 
	    return authProvider;
	}
}
