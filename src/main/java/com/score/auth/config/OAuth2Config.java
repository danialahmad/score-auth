package com.score.auth.config;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	 @Autowired
	 @Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;
	
	 
	 private TokenStore tokenStore;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		//endpoints.authenticationManager(authenticationManager);
		//endpoints.authenticationManager(authenticationManager).accessTokenConverter(
		//		jwtAccessTokenConverter());
		//endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager);
		endpoints.authenticationManager(authenticationManager).userApprovalHandler(userApprovalHandler());
		
	}
	
	@Bean
	public UserApprovalHandler userApprovalHandler() {
		return new DefaultUserApprovalHandler();
	}
	
//	@Bean
//	public ApprovalStore approvalStore(){
//		TokenApprovalStore tokenApprovalStore =new TokenApprovalStore();
//		TokenStore tokenStore=new JwtTokenStore(jwtAccessTokenConverter());
//		tokenApprovalStore.setTokenStore(tokenStore);
//		ApprovalStore approvalStore=tokenApprovalStore;
//		return approvalStore;
//	}
	
//	
//	@Bean
//    @Primary
//    public DefaultTokenServices tokenServices() {
//        DefaultTokenServices tokenServices = new DefaultTokenServices();
//        tokenServices.setSupportRefreshToken(true);
//        tokenServices.setTokenStore(tokenStore ());
//        return tokenServices;
//    }
     
//    @Bean
//    public TokenStore tokenStore() {
//        if (this.tokenStore == null)
//            this.tokenStore = new InMemoryTokenStore();
//         
//        return this.tokenStore;
//    }
	
	@Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) 
      throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }
 

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
		.withClient("acme")
		.secret("acmesecret")
		.authorizedGrantTypes("authorization_code", "refresh_token",
				"password").autoApprove(true).scopes("openid");
		
	}
	
	
//	@Bean
//	public JwtAccessTokenConverter jwtAccessTokenConverter() {
//		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//		KeyPair keyPair = new KeyStoreKeyFactory(
//				new ClassPathResource("keystore.jks"), "foobar".toCharArray())
//				.getKeyPair("test");
//		converter.setKeyPair(keyPair);
//		return converter;
//	}

	

	
	

}
