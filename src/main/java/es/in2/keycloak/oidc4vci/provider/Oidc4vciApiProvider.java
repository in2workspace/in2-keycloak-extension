package es.in2.keycloak.oidc4vci.provider;

import es.in2.keycloak.oidc4vci.service.Oidc4vciService;
import es.in2.keycloak.oidc4vci.service.impl.Oidc4VciServiceImpl;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.model.ErrorResponse;
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

    @GET
    @Path("greetings")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getGreetings() {
        return Response.ok()
                .entity("Welcome to the OIDC4VCI API")
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path(".well-known/openid-configuration")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAuthServerMetadata() {
        return Response.ok()
                .entity(oidc4VCIService.buildOAuth2AuthorizationServerMetadata())
                .header(ACCESS_CONTROL, "*")
                .build();
    }

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


    @POST
    @Path("token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getToken(@FormParam("grant_type") String grantType,
                             @FormParam("pre-authorized_code") String preAuthorizedCode,
                             @FormParam("tx_code") int txCode) {
        try {
            // Verify GrantType is pre-authorized_code
            checkGrantType(grantType);

            // Build Access Token and Token Response
            TokenResponse tokenResponse = oidc4VCIService.buildTokenResponse(session, preAuthorizedCode,txCode);
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

    private void checkGrantType(String grantType) {
        if (!"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            throw new ErrorResponseException(getCustomErrorResponse("unsupported_grant_type", "Unsupported grant type"));
        }
    }
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

