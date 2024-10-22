package es.in2.keycloak.oidc4vci.service;

import org.fikua.model.AuthorizationServerMetadata;
import org.fikua.model.FreshNonceResponse;
import org.fikua.model.PreAuthorizedCodeGrant;
import org.fikua.model.TokenResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AppAuthManager;

public interface Oidc4vciService {
    AuthorizationServerMetadata buildOAuth2AuthorizationServerMetadata();
    PreAuthorizedCodeGrant buildPreAuthorizedCodeGrant(String email, KeycloakSession session, AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator);
    TokenResponse buildTokenResponse(KeycloakSession session, String preAuthorizedCode, int txCode);
    FreshNonceResponse generateFreshNonce(String nonce, AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator);
}
