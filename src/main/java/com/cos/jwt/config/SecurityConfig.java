package com.cos.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.filter.MyFilter3;

import lombok.RequiredArgsConstructor;


@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final CorsFilter corsFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(),BasicAuthenticationFilter.class); //내가 만든 필터보다 먼저 실행됨.
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.addFilter(corsFilter) //@CrossOrigin(인증x), 시큐리티 필터에 등록 인증(o)
		.formLogin().disable()
		.httpBasic().disable()
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
	}
}
