package es.in2.keycloak.oidc4vci.provider;

import es.in2.keycloak.oidc4vci.service.Oidc4vciService;
import es.in2.keycloak.oidc4vci.service.impl.Oidc4VciServiceImpl;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.model.ErrorResponse;
import org.fikua.model.FreshNonceResponse;
import org.fikua.model.PreAuthorizedCodeGrant;
import org.fikua.model.TokenResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.resource.RealmResourceProvider;

@Slf4j
@Path("vci")
public class Oidc4vciApiProvider implements RealmResourceProvider {

    public static final String ACCESS_CONTROL = "Access-Control-Allow-Origin";

    private final KeycloakSession session;

    public Oidc4vciApiProvider(KeycloakSession session) {
        this.session = session;
    }

    private final Oidc4vciService oidc4VCIService = new Oidc4VciServiceImpl();

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        log.info("Closing Oidc4vciApiProvider");
    }

    /**
     * Returns a greeting message when this endpoint is accessed.
     * This can be used to verify that the service is operational.
     */
    @GET
    @Path("greetings")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getGreetings() {
        return Response.ok()
                .entity("Welcome to the OIDC4VCI API")
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    /**
     * Retrieves the OAuth 2.0 Authorization Server metadata.
     * This information is required by clients to interact with the authorization server.
     */
    @GET
    @Path(".well-known/openid-configuration")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAuthServerMetadata() {
        return Response.ok()
                .entity(oidc4VCIService.buildOAuth2AuthorizationServerMetadata())
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    /**
     * Provides the pre-authorized code and transaction code to the client.
     * The email is used to send the transaction code via another channel.
     *
     * @param email the email address to send the transaction code.
     * @return a pre-authorized code along with a transaction code.
     */
    @GET
    @Path("pre-authorized-code")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getPreAuthorizedCode(@QueryParam("email") String email) {
        if (email == null || email.isEmpty()) {
            return getCustomErrorResponse("invalid_request", "Email parameter is missing");
        }

        // Create BearerTokenAuthenticator instance here
        AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator = new AppAuthManager.BearerTokenAuthenticator(session);

        // Issue the pre-authorized code and send the tx_code via email
        PreAuthorizedCodeGrant preAuthorizedCodeGrant = oidc4VCIService.buildPreAuthorizedCodeGrant(email, session, bearerTokenAuthenticator);

        return Response.ok()
                .entity(preAuthorizedCodeGrant)
                .header(ACCESS_CONTROL, "*")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    /**
     * Endpoint to exchange a pre-authorized code and transaction code for an access token.
     *
     * @param grantType the type of grant (pre-authorized code).
     * @param preAuthorizedCode the pre-authorized code issued earlier.
     * @param txCode the transaction code issued to bind the request.
     * @return the generated access token and related information.
     */
    @POST
    @Path("token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getToken(@FormParam("grant_type") String grantType,
                             @FormParam("pre-authorized_code") String preAuthorizedCode,
                             @FormParam("tx_code") int txCode) {
        try {
            // Verify the GrantType is pre-authorized_code
            checkGrantType(grantType);

            // Build Access Token and Token Response
            TokenResponse tokenResponse = oidc4VCIService.buildTokenResponse(session, preAuthorizedCode, txCode);
            return Response.ok()
                    .entity(tokenResponse)
                    .header(ACCESS_CONTROL, "*")
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .build();
        } catch (ErrorResponseException e) {
            return Response.fromResponse(e.getResponse())
                    .entity(e.getResponse())
                    .header(ACCESS_CONTROL, "*")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    /**
     * Endpoint to validate the provided nonce and generate a fresh nonce.
     *
     * @param nonce the nonce to be validated.
     * @return a fresh nonce and the expiration time of the nonce.
     */
    @POST
    @Path("validate-nonce")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateNonce(@FormParam("nonce") String nonce) {
        try {
            AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator = new AppAuthManager.BearerTokenAuthenticator(session);

            // Validate nonce logic in the service
            FreshNonceResponse freshNonceResponse = oidc4VCIService.generateFreshNonce(nonce, bearerTokenAuthenticator);

            return Response.ok()
                    .entity(freshNonceResponse)
                    .header(ACCESS_CONTROL, "*")
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .build();

        } catch (ErrorResponseException e) {
            return Response.fromResponse(e.getResponse())
                    .entity(e.getResponse())
                    .header(ACCESS_CONTROL, "*")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    /**
     * Checks if the provided grant type is valid (pre-authorized code).
     * If the grant type is unsupported, throws an error.
     *
     * @param grantType the grant type to be verified.
     */
    private void checkGrantType(String grantType) {
        if (!"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            throw new ErrorResponseException(getCustomErrorResponse("unsupported_grant_type", "Unsupported grant type"));
        }
    }

    /**
     * Returns a custom error response in case of an invalid request or error.
     *
     * @param error the error code.
     * @param message the error message.
     * @return a Response object containing the error details.
     */
    private Response getCustomErrorResponse(String error, String message) {
        ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.setError(ErrorResponse.ErrorEnum.valueOf(error));
        errorResponse.setMessage(message);

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorResponse)
                .header(ACCESS_CONTROL, "*")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}

