package es.in2.keycloak.oidc4vci.service.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import es.in2.keycloak.oidc4vci.exception.EmailSendingException;
import es.in2.keycloak.oidc4vci.service.Oidc4vciService;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fikua.model.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static es.in2.keycloak.config.KeycloakConfig.*;
import static es.in2.keycloak.oidc4vci.util.Oidc4vciUtils.generateCustomNonce;

@Slf4j
@RequiredArgsConstructor
public class Oidc4VciServiceImpl implements Oidc4vciService {

    private static final Cache<String, Object> cache = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .concurrencyLevel(Runtime.getRuntime().availableProcessors())
            .build();

    public PreAuthorizedCodeGrant buildPreAuthorizedCodeGrant(String email, KeycloakSession session, AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator) {
        // Step 1: Generate and store pre-authorized code
        String preAuthorizedCodeValue = generatePreAuthorizedCode(bearerTokenAuthenticator, session);

        // Step 2: Generate and store tx_code value
        int txCodeValue = generateTxCodeValue();

        // Store pre-authorized code and the tx_code in the cache
        cache.put(preAuthorizedCodeValue, txCodeValue);

        // Step 3: Send the tx_code via email (assuming handled by another service)
        sendTxCodeEmail(email, txCodeValue, session);

        // Step 4: Create tx_code object
        PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode txCode =
                new PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode()
                        .inputMode("numeric")  // Example: Always numeric
                        .length(getTxCodeSize())  // Example: Transaction code length
                        .description(getTxCodeDescription());  // Example: Description to guide the user

        // Step 5: Create and return the PreAuthorizedCodeGrant object
        return new PreAuthorizedCodeGrant()
                .urnColonIetfColonParamsColonOauthColonGrantTypeColonPreAuthorizedCode(new PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCode()
                        .preAuthorizedCode(preAuthorizedCodeValue)  // Set pre-authorized code
                        .txCode(txCode)
                );
    }


    /**
     * If the provided tx_code don't match with the one bounded with the pre-authorized_code in cache throw error.
     *
     * @param preAuthorizedCode - preAuthorizedCode
     * @param txCode            - txCode
     */
    private void verifyTxCode(int txCode, String preAuthorizedCode) {
        if (!Objects.equals(cache.getIfPresent(preAuthorizedCode), txCode)) {
            cache.invalidate(preAuthorizedCode);
            throw new ErrorResponseException(Response
                    .status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse().error(ErrorResponse.ErrorEnum.INVALID_TX_CODE))
                    .build());
        }
    }

    public TokenResponse buildTokenResponse(KeycloakSession session, String preAuthorizedCode, int txCode) {
        // Step 1: Verify tx_code with the pre-authorized_code
        verifyTxCode(txCode, preAuthorizedCode);
        // Build EventBuilder
        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session,
                session.getContext().getConnection());
        // Parse the pre-authorized_code
        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, preAuthorizedCode,
                session.getContext().getRealm(), eventBuilder);
        // Check if the code is expired or illegal
        checkIfCodeIsExpiredOrIllegal(result);
        // Set the realm and client in the session context
        session.getContext().setRealm(result.getClientSession().getRealm());
        session.getContext().setClient(result.getClientSession().getClient());
        // Create the client access token
        AccessToken accessToken = new TokenManager().createClientAccessToken(session,
                result.getClientSession().getRealm(),
                result.getClientSession().getClient(),
                result.getClientSession().getUserSession().getUser(),
                result.getClientSession().getUserSession(),
                DefaultClientSessionContext.fromClientSessionAndScopeParameter(result.getClientSession(),
                        OAuth2Constants.SCOPE_OPENID, session));
        // setting custom expiration time from env variables
        accessToken.exp((long) (getTokenExpiration() + Time.currentTime()));
        String encryptedToken = session.tokens().encodeAndEncrypt(accessToken);

        // Build c_nonce and c_nonce_expires_in
        long expiresIn = accessToken.getExp() - Time.currentTime();
        String nonce = generateCustomNonce();
        cache.put(nonce, nonce);

        // Build and return TokenResponse
        return getTokenResponse(encryptedToken, expiresIn, nonce);
    }

    private static TokenResponse getTokenResponse(String encryptedToken, long expiresIn, String nonce) {
        long nonceExpiresIn = (int) TimeUnit.SECONDS.convert(getPreAuthLifespan(), getPreAuthLifespanTimeUnit());
        // Build Authorization Details


        // Build and return TokenResponse
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken(encryptedToken);
        tokenResponse.setTokenType(TokenResponse.TokenTypeEnum.BEARER);
        tokenResponse.setExpiresIn(BigDecimal.valueOf(expiresIn));
        tokenResponse.setcNonce(nonce);
        tokenResponse.setcNonceExpiresIn(BigDecimal.valueOf(nonceExpiresIn));
        return tokenResponse;
    }

    private void checkIfCodeIsExpiredOrIllegal(OAuth2CodeParser.ParseResult result) {
        if (result.isExpiredCode() || result.isIllegalCode()) {
            throw new ErrorResponseException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse()
                            .error(ErrorResponse.ErrorEnum.INVALID_TOKEN)
                            .message("Invalid pre-authorized_code"))
                    .build());
        }
    }

    public AuthorizationServerMetadata buildOAuth2AuthorizationServerMetadata() {
        AuthorizationServerMetadata authorizationServerMetadata = new AuthorizationServerMetadata();
        authorizationServerMetadata.setIssuer(getIssuerExternalUrl());
        authorizationServerMetadata.setPreAuthorizedGrantEndpoint(getIssuerExternalUrl() + "/pre-authorized-code");
        authorizationServerMetadata.addGrantTypesSupportedItem(AuthorizationServerMetadata.GrantTypesSupportedEnum.URN_IETF_PARAMS_OAUTH_GRANT_TYPE_PRE_AUTHORIZED_CODE);
        authorizationServerMetadata.addResponseTypesSupportedItem(AuthorizationServerMetadata.ResponseTypesSupportedEnum.TOKEN);
        authorizationServerMetadata.setPreAuthorizedGrantAnonymousAccessSupported(true);
        return authorizationServerMetadata;
    }

    private String generatePreAuthorizedCode(AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator, KeycloakSession session) {
        AuthenticationManager.AuthResult authResult = validateAuthentication(bearerTokenAuthenticator);
        UserSessionModel userSessionModel = authResult.getSession();

        AuthenticatedClientSessionModel clientSessionModel = userSessionModel
                .getAuthenticatedClientSessionByClient(authResult.getClient().getId());

        String preAuthorizedCode = generateCustomNonce();
        int expiration = Time.currentTime() + (int) TimeUnit.SECONDS.convert(getPreAuthLifespan(), getPreAuthLifespanTimeUnit());

        // Step 4: Create the OAuth2Code object with only the relevant fields
        OAuth2Code oAuth2Code = new OAuth2Code(preAuthorizedCode, expiration, null, null, null, null, null, userSessionModel.getId());

        // Step 5: Persist the OAuth2Code and return the code
        return customPersistCode(session, clientSessionModel, oAuth2Code, expiration);
    }
    public static String customPersistCode(KeycloakSession session, AuthenticatedClientSessionModel clientSession, OAuth2Code codeData, int expiration) {
        SingleUseObjectProvider codeStore = session.singleUseObjects();
        String key = codeData.getId();

        if (key == null) {
            throw new IllegalStateException("ID not present in the data");
        }

        Map<String, String> serialized = codeData.serializeCode();
        codeStore.put(key, expiration, serialized);

        return key + "." + clientSession.getUserSession().getId() + "." + clientSession.getClient().getId();
    }


    public int generateTxCodeValue() {
        SecureRandom random = new SecureRandom();
        int codeSize = getTxCodeSize();
        double minValue = Math.pow(10, (double) codeSize - 1);
        double maxValue = Math.pow(10, codeSize) - 1;
        // Generate a random number within the specified range.
        return random.nextInt((int) (maxValue - minValue + 1)) + (int) minValue;
    }

    public void sendTxCodeEmail(String email, int txCode, KeycloakSession session) {
        try {
            EmailSenderProvider emailSender = session.getProvider(EmailSenderProvider.class);

            // Definir el cuerpo del correo en texto simple (opcional)
            String textBody = "Hello,\nYour PIN code is: " + txCode + "\nPlease enter this PIN code in your Wallet App.";

            // Definir el cuerpo del correo en HTML, reemplazando el pin dinámicamente
            String htmlBody = "<!DOCTYPE html>\n" +
                    "<html lang=\"en\">\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>Your PIN Code</title>\n" +
                    "    <style>\n" +
                    "        body {\n" +
                    "            font-family: Arial, sans-serif;\n" +
                    "            background-color: #f4f4f9;\n" +
                    "            margin: 0;\n" +
                    "            padding: 0;\n" +
                    "            color: #333;\n" +
                    "            line-height: 1.6;\n" +
                    "        }\n" +
                    "        .container {\n" +
                    "            max-width: 600px;\n" +
                    "            margin: 20px auto;\n" +
                    "            padding: 20px;\n" +
                    "            background-color: #fff;\n" +
                    "            border-radius: 8px;\n" +
                    "            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);\n" +
                    "            border: 1px solid #ddd;\n" +
                    "        }\n" +
                    "        .header {\n" +
                    "            background-color: #224178;\n" +
                    "            color: #fff;\n" +
                    "            padding: 10px;\n" +
                    "            border-radius: 8px 8px 0 0;\n" +
                    "            text-align: center;\n" +
                    "        }\n" +
                    "        .header h1 {\n" +
                    "            margin: 0;\n" +
                    "            font-size: 24px;\n" +
                    "        }\n" +
                    "        .content {\n" +
                    "            padding: 20px;\n" +
                    "            text-align: center;\n" +
                    "        }\n" +
                    "        .content p {\n" +
                    "            margin: 0 0 10px;\n" +
                    "        }\n" +
                    "        .pin {\n" +
                    "            display: inline-block;\n" +
                    "            padding: 10px 20px;\n" +
                    "            font-size: 32px;\n" +
                    "            color: #224178;\n" +
                    "            background-color: #dae4ed;\n" +
                    "            border-radius: 5px;\n" +
                    "            margin: 20px 0;\n" +
                    "            font-weight: bold;\n" +
                    "            letter-spacing: 2px;\n" +
                    "        }\n" +
                    "        .footer {\n" +
                    "            text-align: center;\n" +
                    "            padding: 10px;\n" +
                    "            font-size: 14px;\n" +
                    "            color: #777;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "<div class=\"container\">\n" +
                    "    <div class=\"header\">\n" +
                    "        <h1>Your PIN Code</h1>\n" +
                    "    </div>\n" +
                    "    <div class=\"content\">\n" +
                    "        <p>Hello,</p>\n" +
                    "        <p>Your PIN code is:</p>\n" +
                    "        <p><strong class=\"pin\">" + txCode + "</strong></p>\n" +
                    "        <p>Please enter this PIN code in your Wallet App.</p>\n" +
                    "    </div>\n" +
                    "    <div class=\"footer\">\n" +
                    "        <p>If you did not request this PIN, please ignore this email.</p>\n" +
                    "    </div>\n" +
                    "</div>\n" +
                    "</body>\n" +
                    "</html>";

            // Usar el método send() para enviar el email con cuerpo de texto y HTML
            emailSender.send(session.getContext().getRealm().getSmtpConfig(), email, "Your PIN Code", textBody, htmlBody);
        } catch (EmailException e) {
            throw new EmailSendingException("Error sending email", e);
        }
    }

    private AuthenticationManager.AuthResult validateAuthentication(AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator) {
        AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
        if (authResult == null) {
            throw new ErrorResponseException(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse().error(ErrorResponse.ErrorEnum.INVALID_TOKEN))
                    .build());
        }
        return authResult;
    }

}
