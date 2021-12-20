package com.liferay.samples.fbo.oidc.userinfo.mapping.action;

import com.liferay.portal.kernel.events.ActionException;
import com.liferay.portal.kernel.events.LifecycleAction;
import com.liferay.portal.kernel.events.LifecycleEvent;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectProvider;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectProviderRegistry;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectServiceException.ProviderException;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectSession;
import com.liferay.portal.security.sso.openid.connect.provider.OpenIdConnectSessionProvider;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;

import javax.servlet.http.HttpSession;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component(
		immediate = true, property = "key=login.events.post",
		service = LifecycleAction.class
	)
public class OIDCRoleMappingPostLoginAction implements LifecycleAction {

	private final static Logger LOG = LoggerFactory.getLogger(OIDCRoleMappingPostLoginAction.class);

	protected OpenIdConnectSession getOpenIdConnectSession(HttpSession httpSession) {

		Object openIdConnectSessionObject =
			_openIdConnectSessionProvider.getOpenIdConnectSession(
				httpSession);

		if (openIdConnectSessionObject instanceof OpenIdConnectSession) {
			OpenIdConnectSession openIdConnectSession =
				(OpenIdConnectSession)openIdConnectSessionObject;

			return openIdConnectSession;
		}

		return null;
	}
	
	@Override
	public void processLifecycleEvent(LifecycleEvent lifecycleEvent) throws ActionException {

		HttpSession httpSession = lifecycleEvent.getRequest().getSession(false);

		OpenIdConnectSession openIdConnectSession = getOpenIdConnectSession(httpSession);
		
		if(openIdConnectSession == null) {
			LOG.debug("Skipping action, the user did not sign in with OIDC");
			return;
		}
		
		String accessToken = openIdConnectSession.getAccessTokenValue();
		
		LOG.debug("OIDC Access token: {}", accessToken);
	
		String openIdProviderName = openIdConnectSession.getOpenIdProviderName();
				
		OpenIdConnectProvider<OIDCClientMetadata, OIDCProviderMetadata> openIdConnectProvider;
		try {
			openIdConnectProvider = _openIdConnectProviderRegistry.findOpenIdConnectProvider(
			_portal.getCompanyId(lifecycleEvent.getRequest()), openIdProviderName);
		} catch (ProviderException e) {
			LOG.error("Failed to get OpenID Connect Provider", e);
			return;
		}
		
		
		URI userInfoEndpointURI = null;
		
		try {
			userInfoEndpointURI = openIdConnectProvider.getOIDCProviderMetadata().getUserInfoEndpointURI();
			
			HttpURLConnection con = (HttpURLConnection) userInfoEndpointURI.toURL().openConnection();
			
			con.setRequestMethod("GET");
			con.setRequestProperty("Authorization", "Bearer " + accessToken);
			
			int status = con.getResponseCode();
			
			LOG.debug("UserInfo endpoint from OpenID Provider <{}> responsed with status <{}>", openIdProviderName, status);
			
			BufferedReader in = new BufferedReader(
					  new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer content = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				content.append(inputLine);
			}
			in.close();
			
			LOG.debug("UserInfo endpoint from OpenID Provider <{}> replied {}", openIdProviderName, content.toString());
			
			// TODO: Do whatever you want with the data retrieved from user info			
			
		} catch (ProviderException e) {
			LOG.error("Failed to get UserInfo endpoint URI from OpenID Provider <{}> metadata, please check OIDC configuration", openIdProviderName, e);
		} catch (MalformedURLException e) {
			LOG.error("UserInfo endpoint URI <{}> from OpenID Provider <{}> metadata is malformed", userInfoEndpointURI, openIdProviderName, e);
		} catch (IOException e) {
			LOG.error("Failed to connect to UserInfo endpoint URI <{}> from OpenID Provider <{}>", userInfoEndpointURI, openIdProviderName, e);
		}		
		
	}

	@Reference
	private OpenIdConnectProviderRegistry<OIDCClientMetadata, OIDCProviderMetadata> _openIdConnectProviderRegistry;
	
	@Reference
	private Portal _portal;
	
	@Reference
	private OpenIdConnectSessionProvider _openIdConnectSessionProvider;
}