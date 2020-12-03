# OpenID Connect UserInfo data mapping

Vanilla Liferay does not allow you to map additional data from the ID Token through configuration.

However, through some programming, it is possible to process some information from the OpenID Provider's UserInfo
endpoint.

For the moment, it is required to create a fragment so that one of the Liferay OSGI bundles
exports some required model classes that describe the OpenID Provider Metadata (I need to be able to fetch
the user info endpoint from the Liferay configuration).

This is not really OK. That's why I've filled an issue: https://issues.liferay.com/browse/LPS-116678

Then, all you need to do is to retrieve the Access Token from the OIDC session in a Post Login Action and
use it to make an HTTP request to the OpenID Provider's UserInfo endpoint: that's the second endpoint.

This module was tested with Liferay DXP 7.2 SP3 and Keycloak 11.0.0 acting as the OpenId Provider.