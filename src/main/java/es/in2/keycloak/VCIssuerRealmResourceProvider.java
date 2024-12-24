package es.in2.keycloak;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import es.in2.keycloak.model.*;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.fiware.keycloak.oidcvc.model.SupportedCredentialVO;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.urls.UrlType;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static es.in2.keycloak.controller.SIOP2ClientRegistrationProvider.VC_TYPES_PREFIX;

/**
 * Real-Resource to provide functionality for issuing VerfiableCredentials to users, depending on there roles in
 * registered SIOP-2 clients
 */
public class VCIssuerRealmResourceProvider implements RealmResourceProvider {

    private static final Logger LOGGER = Logger.getLogger(VCIssuerRealmResourceProvider.class);

    public static final String LD_PROOF_TYPE = "LD_PROOF";
    public static final String CREDENTIAL_PATH = "credential";
    public static final String TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential";
    public static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final String ACCESS_CONTROL = "Access-Control-Allow-Origin";
    private static Cache<String, String> cache;
    private final KeycloakSession session;
    private final String issuerDid;
    private final AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;
    private final Clock clock;
    private static final SecureRandom random = new SecureRandom();
    // Optional parameters for cache settings
    private static Long customDuration = null;
    private static TimeUnit customTimeUnit = null;
    private static int txCodeSize = 4;
    private static String txCodeDescription = "A PIN has been sent to your email. Check your inbox. Enter your PIN Code.";

    public VCIssuerRealmResourceProvider(KeycloakSession session, String issuerDid,
                                         AppAuthManager.BearerTokenAuthenticator authenticator, Clock clock) {
        this(session, issuerDid, authenticator, clock, null, null);
    }

    public VCIssuerRealmResourceProvider(KeycloakSession session, String issuerDid,
                                         AppAuthManager.BearerTokenAuthenticator authenticator, Clock clock,
                                         Long duration, TimeUnit timeUnit) {
        this.session = session;
        this.issuerDid = issuerDid;
        this.bearerTokenAuthenticator = authenticator;
        this.clock = clock;
        if (duration != null && timeUnit != null) {
            customDuration = duration;
            customTimeUnit = timeUnit;
        }
        initializeCache();
    }

    private static synchronized void initializeCache() {
        if (cache == null) {
            long duration = customDuration != null ? customDuration : getPreAuthLifespan();
            TimeUnit timeUnit = customTimeUnit != null ? customTimeUnit : getPreAuthLifespanTimeUnit();
            cache = CacheBuilder.newBuilder()
                    .expireAfterWrite(duration, timeUnit)
                    .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                    .build();
        }
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // no specific resources to close.
    }

    private UserModel getUserModel(ErrorResponseException errorResponse) {
        return getAuthResult(errorResponse).getUser();
    }

    private UserSessionModel getUserSessionModel() {
        return getAuthResult(new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN))).getSession();
    }

    private AuthenticationManager.AuthResult getAuthResult() {
        return getAuthResult(new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN)));
    }

    private AuthenticationManager.AuthResult getAuthResult(ErrorResponseException errorResponse) {
        AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
        if (authResult == null) {
            throw errorResponse;
        }
        return authResult;
    }

    private UserModel getUserModel() {
        return getUserModel(new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN)));
    }

    private void assertIssuerDid(String requestedIssuerDid) {
        if (!requestedIssuerDid.equals(issuerDid)) {
            throw new ErrorResponseException("not_found", "No such issuer exists.", Response.Status.NOT_FOUND);
        }
    }

    private Response getErrorResponse(ErrorType errorType) {
        return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(errorType.getValue())).build();
    }

    @GET
    @Path("{issuer-did}/.well-known/openid-configuration")
    @Produces({MediaType.APPLICATION_JSON})
    @ApiOperation(value = "Return the authorization server metadata", tags = {})
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The authorization server metadata", response = AuthorizationServerMetadata.class)})
    public Response getAuthServerMetadata(@PathParam("issuer-did") String issuerDidParam) {
        LOGGER.info("Retrieve authorization server metadata");
        assertIssuerDid(issuerDidParam);
        String tokenEndpointPattern = "%s/token";

        return Response.ok().entity(new AuthorizationServerMetadata(String.format(tokenEndpointPattern, getIssuerExternalUrl())))
                .header(ACCESS_CONTROL, "*").build();
    }

    private String getCredentialEndpoint() {
        return getIssuer() + "/" + CREDENTIAL_PATH;
    }

    private String getIssuer() {
        return String.format("%s/%s/%s", getRealmResourcePath(),
                VCIssuerRealmResourceProviderFactory.ID,
                issuerDid);
    }

    private List<SupportedCredentialVO> getSupportedCredentials(KeycloakContext context) {
        return context.getRealm().getClientsStream()
                .flatMap(cm -> cm.getAttributes().entrySet().stream())
                .filter(entry -> entry.getKey().startsWith(VC_TYPES_PREFIX))
                .flatMap(entry -> mapAttributeEntryToScVO(entry).stream())
                .collect(Collectors.toList());

    }

    private List<SupportedCredentialVO> mapAttributeEntryToScVO(Map.Entry<String, String> typesEntry) {
        String type = typesEntry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
        Set<FormatVO> supportedFormats = getFormatsFromString(typesEntry.getValue());
        return supportedFormats.stream().map(formatVO -> {
                    String id = buildIdFromType(formatVO, type);
                    return new SupportedCredentialVO().id(id).types(List.of(type)).format(formatVO);
                }
        ).collect(Collectors.toList());
    }

    private Set<FormatVO> getFormatsFromString(String formatString) {
        return Arrays.stream(formatString.split(",")).map(FormatVO::fromValue).collect(Collectors.toSet());
    }

    private String buildIdFromType(FormatVO formatVO, String type) {
        return String.format("%s_%s", type, formatVO.toString());
    }

    private String getRealmResourcePath() {
        KeycloakContext currentContext = session.getContext();
        String realm = currentContext.getRealm().getName();
        String backendUrl = currentContext.getUri(UrlType.BACKEND).getBaseUri().toString();
        if (backendUrl.endsWith("/")) {
            return String.format("%srealms/%s", backendUrl, realm);
        }
        return String.format("%s/realms/%s", backendUrl, realm);
    }

    @GET
    @Path("{issuer-did}/credential-offer")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialOffer(@PathParam("issuer-did") String issuerDidParam,
                                       @QueryParam("type") String vcType, @QueryParam("format") String formatString) {

        FormatVO format = Optional.ofNullable(formatString).map(FormatVO::fromValue)
                .orElseThrow(() -> new ErrorResponseException(getErrorResponse(ErrorType.valueOf("Invalid format"))));

        LOGGER.infof("Get an offer for %s - %s", vcType, format);
        assertIssuerDid(issuerDidParam);
        // workaround to support implementations not differentiating json & json-ld
        if (format == FormatVO.JWT_VC) {
            // validate that the user is able to get the offered credentials
            getClientsOfType(vcType, FormatVO.JWT_VC_JSON);
        } else {
            getClientsOfType(vcType, format);
        }

        // Generate pre-authorized code and PIN and save them in cache
        String preAuthorizedCode = generateAuthorizationCode();
        String pin = String.valueOf(generateRandomPin());
        cache.put(preAuthorizedCode, pin);
        Grant grant = new Grant(
                preAuthorizedCode,
                Grant.TxCode.builder().description(txCodeDescription).length(txCodeSize).build()
        );
        PreAuthCodeResponse preAuthCodeResponse = PreAuthCodeResponse.builder().grant(grant).pin(pin).build();
        return Response.ok()
                .entity(preAuthCodeResponse)
                .header(ACCESS_CONTROL, "*")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    public String generateAuthorizationCode() {
        AuthenticationManager.AuthResult authResult = getAuthResult();

        UserSessionModel userSessionModel = getUserSessionModel();

        AuthenticatedClientSessionModel clientSessionModel = userSessionModel.
                getAuthenticatedClientSessionByClient(
                        authResult.getClient().getId());

        int expiration = Time.currentTime() + (int) TimeUnit.SECONDS.convert(getPreAuthLifespan(), getPreAuthLifespanTimeUnit());
        String codeId = UUID.randomUUID().toString();

        String nonce = UUID.randomUUID().toString();

        OAuth2Code oAuth2Code = new OAuth2Code(codeId, expiration, nonce, null, null,
                null, null, userSessionModel.getId());

        return customPersistCode(session, clientSessionModel, oAuth2Code, expiration);
    }

    public int generateRandomPin() {
        int codeSize = txCodeSize;
        double minValue = Math.pow(10, (double) codeSize - 1);
        double maxValue = Math.pow(10, codeSize) - 1;
        // Generate a random number within the specified range.
        return random.nextInt((int) (maxValue - minValue + 1)) + (int) minValue;
    }

    // Custom method for persisting PreAuthCode with custom expiration time from env variables
    public static String customPersistCode(KeycloakSession session, AuthenticatedClientSessionModel clientSession, OAuth2Code codeData, int expiration) {
        SingleUseObjectProvider codeStore = session.singleUseObjects();
        String key = codeData.getId();
        if (key == null) {
            throw new IllegalStateException("ID not present in the data");
        } else {
            Map<String, String> serialized = codeData.serializeCode();
            codeStore.put(key, expiration, serialized);
            return key + "." + clientSession.getUserSession().getId() + "." + clientSession.getClient().getId();
        }
    }

    @POST
    @Path("/nonce-valid")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public NonceValidationResponse validateNonce(@FormParam("nonce") String nonce) {
        LOGGER.infof("Check validation of nonce: %s", nonce);

        if (cache.getIfPresent(nonce) != null) {
            cache.invalidate(nonce);
            return new NonceValidationResponse(true);
        } else {
            return new NonceValidationResponse(false);
        }
    }


    @POST
    @Path("{issuer-did}/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response exchangeToken(
            @PathParam("issuer-did") String issuerDidParam,
            @FormParam("grant_type") String grantType,
            @FormParam("code") String code,
            @FormParam("pre-authorized_code") String preauth,
            @FormParam("tx_code") String txCode) {

        LOGGER.infof("Received token request %s - %s - %s - %s.", grantType, code, preauth, txCode);

        assertIssuerDid(issuerDidParam);

        // check if the grant type is pre-authorized_code
        if (!grantType.equals(GRANT_TYPE_PRE_AUTHORIZED_CODE)) {
            LOGGER.errorf("ERROR - Invalid grant type: %s", grantType);
            throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN));
        }

        // if the provided tx_code don't match with the one bounded with the pre-authcode in cache throw error
        if (!Objects.equals(cache.getIfPresent(preauth), txCode)) {
            LOGGER.errorf("ERROR - Invalid tx_code: %s - Expected: %s", txCode, cache.getIfPresent(preauth));
            cache.invalidate(preauth);
            throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TX_CODE));
        } else {
            cache.invalidate(preauth);
        }

        // some (not fully OIDC4VCI compatible) wallets send the preauthorized code as an alternative parameter
        String codeToUse = Optional.ofNullable(code).orElse(preauth);

        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session,
                session.getContext().getConnection());

        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, codeToUse,
                session.getContext().getRealm(),
                eventBuilder);

        if (result.isExpiredCode()) {
            LOGGER.errorf("ERROR - Code %s has expìred.", codeToUse);
            throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN));
        } else if (result.isIllegalCode()) {
            LOGGER.errorf("ERROR - Code %s is illegal.", codeToUse);
            throw new ErrorResponseException(getErrorResponse(ErrorType.INVALID_TOKEN));
        }

        session.getContext().setRealm(result.getClientSession().getRealm());
        session.getContext().setClient(result.getClientSession().getClient());

        AccessToken accessToken = new TokenManager().createClientAccessToken(session,
                result.getClientSession().getRealm(),
                result.getClientSession().getClient(),
                result.getClientSession().getUserSession().getUser(),
                result.getClientSession().getUserSession(),
                DefaultClientSessionContext.fromClientSessionAndScopeParameter(result.getClientSession(),
                        OAuth2Constants.SCOPE_OPENID, session));
        // setting custom expiration time from env variables
        accessToken.expiration(getTokenExpiration() + Time.currentTime());

        String encryptedToken = session.tokens().encodeAndEncrypt(accessToken);
        LOGGER.infof("Successfully returned the token: %s.", encryptedToken);

        String tokenType = "bearer";
        long expiresIn = accessToken.getExp() - Time.currentTime();
        String nonce = generateAndSaveNonce();
        long nonceExpiresIn = (int) TimeUnit.SECONDS.convert(getPreAuthLifespan(), getPreAuthLifespanTimeUnit());

        sendPreAuthCodeAndAccessTokenToIssuer(preauth, encryptedToken);

        return Response.ok().entity(new TokenResponse(encryptedToken, tokenType, expiresIn, nonce, nonceExpiresIn))
                .header(ACCESS_CONTROL, "*")
                .header("Content-Type",  MediaType.APPLICATION_JSON)
                .build();
    }


    // since we cannot know the address of the requesting wallets in advance, we have to accept all origins.
    @OPTIONS
    @Path("{any: .*}")
    public Response optionCorsResponse() {
        return Response.ok().header(ACCESS_CONTROL, "*")
                .header("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type,Authorization")
                .build();
    }

    @NotNull
    private List<ClientModel> getClientsOfType(String vcType, FormatVO format) {
        LOGGER.debugf("Retrieve all clients of type %s, supporting format %s", vcType, format.toString());
        if (format == FormatVO.JWT_VC) {
            // backward compat
            format = FormatVO.JWT_VC_JSON;
        }
        String formatString = format.toString();
        Optional.ofNullable(vcType).filter(type -> !type.isEmpty()).orElseThrow(() -> {
            LOGGER.info("No VC type was provided.");
            return new ErrorResponseException("no_type_provided",
                    "No VerifiableCredential-Type was provided in the request.",
                    Response.Status.BAD_REQUEST);
        });

        String prefixedType = String.format("%s%s", VC_TYPES_PREFIX, vcType);
        LOGGER.infof("Looking for client supporting %s with format %s", prefixedType, formatString);
        List<ClientModel> vcClients = getClientModelsFromSession().stream()
                .filter(clientModel -> Optional.ofNullable(clientModel.getAttributes())
                        .filter(attributes -> attributes.containsKey(prefixedType))
                        .filter(attributes -> Arrays.asList(attributes.get(prefixedType).split(","))
                                .contains(formatString))
                        .isPresent())
                .collect(Collectors.toList());

        if (vcClients.isEmpty()) {
            LOGGER.infof("No SIOP-2-Client supporting type %s registered.", vcType);
            throw new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE));
        }
        return vcClients;
    }

    @NotNull
    private List<ClientModel> getClientModelsFromSession() {
        return session.clients().getClientsStream(session.getContext().getRealm())
                .filter(clientModel -> clientModel.getProtocol() != null)
                .filter(clientModel -> clientModel.getProtocol().equals(SIOP2LoginProtocolFactory.PROTOCOL_ID))
                .collect(Collectors.toList());
    }

    /**
     * Obtains the environment variable ISSUER_API_URL from the docker-compose environment
     */
    private static String getIssuerUrl() {
        return System.getenv("ISSUER_API_URL");
    }

    /**
     * Obtains the environment variable ISSUER_API_EXTERNAL_URL from the docker-compose environment
     */
    private static String getIssuerExternalUrl() {
        return System.getenv("ISSUER_API_EXTERNAL_URL");
    }

    /**
     * Obtains the environment variable PRE_AUTH_LIFESPAN from the docker-compose environment
     */
    private static long getPreAuthLifespan() {
        return Long.parseLong(System.getenv("PRE_AUTH_LIFESPAN"));
    }

    /**
     * Obtains the environment variable PRE_AUTH_LIFESPAN_TIME_UNIT from the docker-compose environment
     */
    private static TimeUnit getPreAuthLifespanTimeUnit() {
        return TimeUnit.valueOf(System.getenv("PRE_AUTH_LIFESPAN_TIME_UNIT").toUpperCase());
    }

    /**
     * Obtains the environment variable TOKEN_EXPIRATION (in seconds) from the docker-compose environment
     */
    private static int getTokenExpiration() {
        return Integer.parseInt(System.getenv("TOKEN_EXPIRATION"));
    }

    public static String generateAndSaveNonce() {
        UUID randomUuid = UUID.randomUUID();
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(randomUuid.getMostSignificantBits());
        byteBuffer.putLong(randomUuid.getLeastSignificantBits());
        byte[] byteArray = byteBuffer.array();
        String nonce = Base64.getUrlEncoder().encodeToString(byteArray);
        cache.put(nonce, nonce);
        return nonce;
    }

    public static void sendPreAuthCodeAndAccessTokenToIssuer(String preAuthCode, String accessToken) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(getIssuerUrl() + "/api/v1/deferred-credential-metadata/nonce");

            String jsonBody = "{\"pre-authorized_code\":\"" + preAuthCode + "\",\"access_token\":\"" + accessToken + "\"}";
            StringEntity entity = new StringEntity(jsonBody);
            httpPost.setEntity(entity);

            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + accessToken);

            try (CloseableHttpResponse response = client.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 201) {
                    LOGGER.debug("Request successful with status code: " + statusCode);
                } else {
                    LOGGER.error("Unexpected response status: " + statusCode);
                    throw new ErrorResponseException("Unexpected response status", "Received status code: " + statusCode,
                            Response.Status.BAD_REQUEST);
                }
            }
        } catch (Exception e) {
            throw new ErrorResponseException("Communication failed", "Error sending data to issuer: " + e.getMessage(),
                    Response.Status.BAD_REQUEST);
        }
    }
}
