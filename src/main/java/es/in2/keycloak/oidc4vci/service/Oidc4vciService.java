package es.in2.keycloak.oidc4vci.service;

import org.fikua.model.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;

public interface Oidc4vciService {
    CredentialIssuerMetadata buildCredentialIssuerMetadata();
    AuthorizationServerMetadata buildOAuth2AuthorizationServerMetadata();
    String buildCredentialOffer(String vcType);
    CredentialOffer getCredentialOfferById(String id) throws ErrorResponseException;
    void verifyTxCode(String txCode, String preAuthorizedCode);
    TokenResponse buildTokenResponse(KeycloakSession session, String preAuthorizedCode);
}
