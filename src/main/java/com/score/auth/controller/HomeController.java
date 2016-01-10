package com.score.auth.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
	
	@Autowired
	ConsumerTokenServices consumerTokenServices;
	private boolean invalidateHttpSession = true;
	private boolean clearAuthentication = true;
	
	
    @RequestMapping("/csrf_token")
   	public String token(HttpServletRequest request) {
    	CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
    	return token.getToken();
   	}
    
	@RequestMapping(value = "/oauth/revoke-token2", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public void logout(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
        String authHeader = request.getHeader("Authorization");
        System.out.println("AUTH HEADER :"+authHeader);
        if (authHeader != null) {
        	String tokenValue = authHeader.replace("Bearer", "").trim();
            System.out.println("TOKEN VALUE :"+tokenValue);
            consumerTokenServices.revokeToken(tokenValue);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null){    
                new SecurityContextLogoutHandler().logout(request, response, authentication);
            }
            SecurityContextHolder.getContext().setAuthentication(null);
        }
    }
	
	@RequestMapping(value = "/oauth/revoke-token", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public void revoke(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
		String tokenValue = request.getParameter("tokenValue");
		if (tokenValue != null) {      	
            System.out.println("TOKEN VALUE :"+tokenValue);
            consumerTokenServices.revokeToken(tokenValue);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null){    
                new SecurityContextLogoutHandler().logout(request, response, authentication);
            }
            SecurityContextHolder.getContext().setAuthentication(null);
        }
    }
}

