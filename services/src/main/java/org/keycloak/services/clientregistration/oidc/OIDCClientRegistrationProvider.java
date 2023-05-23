/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.services.clientregistration.oidc;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSecretConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.mappers.AbstractPairwiseSubMapper;
import org.keycloak.protocol.oidc.mappers.PairwiseSubMapperHelper;
import org.keycloak.protocol.oidc.mappers.SHA256PairwiseSubMapper;
import org.keycloak.protocol.oidc.utils.SubjectType;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.clientregistration.AbstractClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationException;
import org.keycloak.services.clientregistration.ErrorCodes;
import org.keycloak.util.JsonSerialization;
import org.keycloak.TokenVerifier;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static org.keycloak.protocol.oidc.OIDCConfigAttributes.ID_TOKEN_AS_DETACHED_SIGNATURE;
import static org.keycloak.protocol.oidc.OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCClientRegistrationProvider extends AbstractClientRegistrationProvider {

    private static final Logger logger = Logger.getLogger(OIDCClientRegistrationProvider.class);

    public static final String DADOS = "DADOS";
    public static final String PAGTO = "PAGTO";
    public static final String CONTA = "CONTA";
    public static final String CCORR = "CCORR";

    public static final String OU = "OPIBR-";

    private static final List<String> PAGTO_SCOPES = Arrays.asList(
            "openid",
            "payments",
            "consent",
            "consents",
            "resources");

    private static final List<String> DADOS_SCOPES = Arrays.asList(
            "openid",
            "accounts",
            "credit-cards-accounts",
            "customers",
            "invoice-financings",
            "financings",
            "loans",
            "unarranged-accounts-overdraft",
            "consent",
            "consents",
            "resources");

    public OIDCClientRegistrationProvider(KeycloakSession session) {
        super(session);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createOIDC(OIDCClientRepresentation clientOIDC) {
        if (clientOIDC.getClientId() != null) {
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client Identifier included", Response.Status.BAD_REQUEST);
        }

        SoftwareStatement softwareStatement = validateSoftwareStatement(clientOIDC);

        try {
            ClientRepresentation client = DescriptionConverter.toInternal(session, clientOIDC);

            client.getAttributes().put("org_id", softwareStatement.OrgId);

            client.setDescription(softwareStatement.getSoftwareLogoUri());

            List<String> grantTypes = clientOIDC.getGrantTypes();

            if (grantTypes != null && grantTypes.contains(OAuth2Constants.UMA_GRANT_TYPE)) {
                client.setAuthorizationServicesEnabled(true);
            }

            if (!(grantTypes == null || grantTypes.contains(OAuth2Constants.REFRESH_TOKEN))) {
                OIDCAdvancedConfigWrapper.fromClientRepresentation(client).setUseRefreshToken(false);
            }

            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(session, client, this, clientOIDC);
            client = create(oidcContext);

            ClientModel clientModel = session.getContext().getRealm().getClientByClientId(client.getClientId());
            softwareStatement.getRoles().forEach(clientModel::addRole);

            clientModel.setAttribute(REQUEST_OBJECT_REQUIRED, "request or request_uri");
            clientModel.setAttribute(ID_TOKEN_AS_DETACHED_SIGNATURE, "true");

            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            validateClient(clientModel, clientOIDC, true);

            URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
            clientOIDC = DescriptionConverter.toExternalResponse(session, client, uri);
            clientOIDC.setClientIdIssuedAt(Time.currentTime());
            return Response.created(uri).entity(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @GET
    @Path("{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOIDC(@PathParam("clientId") String clientId) {
        ClientModel client = session.getContext().getRealm().getClientByClientId(clientId);

        ClientRepresentation clientRepresentation = get(client);

        OIDCClientRepresentation clientOIDC = DescriptionConverter.toExternalResponse(session, clientRepresentation, session.getContext().getUri().getRequestUri());
        return Response.ok(clientOIDC).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateOIDC(@PathParam("clientId") String clientId, OIDCClientRepresentation clientOIDC) {
        SoftwareStatement softwareStatement = validateSoftwareStatement(clientOIDC);

        try {
            ClientRepresentation client = DescriptionConverter.toInternal(session, clientOIDC);
            
            client.setDescription(softwareStatement.getSoftwareLogoUri());

            OIDCClientRegistrationContext oidcContext = new OIDCClientRegistrationContext(session, client, this, clientOIDC);
            client = update(clientId, oidcContext);

            ClientModel clientModel = session.getContext().getRealm().getClientByClientId(client.getClientId());

            clientModel.setAttribute(ID_TOKEN_AS_DETACHED_SIGNATURE, "true");

            updatePairwiseSubMappers(clientModel, SubjectType.parse(clientOIDC.getSubjectType()), clientOIDC.getSectorIdentifierUri());
            updateClientRepWithProtocolMappers(clientModel, client);

            client.setSecret(clientModel.getSecret());
            client.getAttributes().put(ClientSecretConstants.CLIENT_SECRET_EXPIRATION,clientModel.getAttribute(ClientSecretConstants.CLIENT_SECRET_EXPIRATION));
            client.getAttributes().put(ClientSecretConstants.CLIENT_SECRET_CREATION_TIME,clientModel.getAttribute(ClientSecretConstants.CLIENT_SECRET_CREATION_TIME));

            validateClient(clientModel, clientOIDC, false);

            URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(client.getClientId()).build();
            clientOIDC = DescriptionConverter.toExternalResponse(session, client, uri);
            return Response.ok(clientOIDC).build();
        } catch (ClientRegistrationException cre) {
            ServicesLogger.LOGGER.clientRegistrationException(cre.getMessage());
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, "Client metadata invalid", Response.Status.BAD_REQUEST);
        }
    }

    @DELETE
    @Path("{clientId}")
    public void deleteOIDC(@PathParam("clientId") String clientId) {
        delete(clientId);
    }

    private void updatePairwiseSubMappers(ClientModel clientModel, SubjectType subjectType, String sectorIdentifierUri) {
        if (subjectType == SubjectType.PAIRWISE) {

            // See if we have existing pairwise mapper and update it. Otherwise create new
            AtomicBoolean foundPairwise = new AtomicBoolean(false);

            clientModel.getProtocolMappersStream().filter((ProtocolMapperModel mapping) -> {
                if (mapping.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX)) {
                    foundPairwise.set(true);
                    return true;
                } else {
                    return false;
                }
            }).collect(Collectors.toList()).forEach((ProtocolMapperModel mapping) -> {
                PairwiseSubMapperHelper.setSectorIdentifierUri(mapping, sectorIdentifierUri);
                clientModel.updateProtocolMapper(mapping);
            });

            // We don't have existing pairwise mapper. So create new
            if (!foundPairwise.get()) {
                ProtocolMapperRepresentation newPairwise = SHA256PairwiseSubMapper.createPairwiseMapper(sectorIdentifierUri, null);
                clientModel.addProtocolMapper(RepresentationToModel.toModel(newPairwise));
            }

        } else {
            // Rather find and remove all pairwise mappers
            clientModel.getProtocolMappersStream()
                    .filter(mapperRep -> mapperRep.getProtocolMapper().endsWith(AbstractPairwiseSubMapper.PROVIDER_ID_SUFFIX))
                    .collect(Collectors.toList())
                    .forEach(clientModel::removeProtocolMapper);
        }
    }

    private void updateClientRepWithProtocolMappers(ClientModel clientModel, ClientRepresentation rep) {
        List<ProtocolMapperRepresentation> mappings =
                clientModel.getProtocolMappersStream().map(ModelToRepresentation::toRepresentation).collect(Collectors.toList());
        rep.setProtocolMappers(mappings);
    }

    private SoftwareStatement validateSoftwareStatement(OIDCClientRepresentation oidcClient) {
        JsonWebToken token;
        List<String> roles;
        try {
            String ssaToken = oidcClient.getSoftwareStatement();

            HttpGet request = new HttpGet("https://keystore.sandbox.directory.opinbrasil.com.br/openinsurance.jwks");
            try (CloseableHttpClient httpClient = HttpClientBuilder.create().build();
                 CloseableHttpResponse response = httpClient.execute(request)) {
                int status = response.getStatusLine().getStatusCode();
                if (status != HttpStatus.SC_OK) {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        ServicesLogger.LOGGER.clientRegistrationException(EntityUtils.toString(entity));
                    }
                    throw new Exception("Failed to fetch the SSA key");
                }
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    throw new Exception("JWKS not found");
                }

                try (InputStream is = entity.getContent()) {
                    JSONWebKeySet jwks = JsonSerialization.readValue(is, JSONWebKeySet.class);

                    JWK jwk = jwks.getKeys()[0];
                    JWKParser parser = JWKParser.create(jwk);

                    token = TokenVerifier.create(ssaToken, JsonWebToken.class)
                            .publicKey(parser.toPublicKey())
                            .verify()
                            .getToken();

                    //verifica se a assinatura é válida.
                    if (token == null) {
                        throw new Exception("Invalid SSA token");
                    }
                }
            }
        } catch (Exception e) {
            logger.error(e);
            throw new ErrorResponseException(ErrorCodes.INVALID_SOFTWARE_STATEMENT, e.getMessage(),
                    Response.Status.BAD_REQUEST);
        }

        try {
            int currentMillis = (int) (System.currentTimeMillis() / 1000);
            int expirationMillis = (int) (token.getIat().intValue() + TimeUnit.MINUTES.toSeconds(5));

            if (currentMillis >= expirationMillis) {
                // throw new Exception("IssuedAt must be at most five minutes ago");
            }

            // valida o jwks uri
            Object jwksUriClaim = token.getOtherClaims().get("software_jwks_uri");
            if (jwksUriClaim != null) {
                String jwksUri = oidcClient.getJwksUri();
                if (!jwksUriClaim.toString().equals(jwksUri)) {
                    throw new Exception("[software_jwks_uri] must be equals to [jwks_uri].");
                }
            } else {
                throw new Exception("[software_jwks_uri] not found in SSA.");
            }

            // valida o redirect uris
            List<String> ssaRedirectUris = new ArrayList<>();
            Object redirectUriClaim = token.getOtherClaims().get("software_redirect_uris");
            if (redirectUriClaim != null) {
                ssaRedirectUris = (ArrayList) redirectUriClaim;
            }
            if (ssaRedirectUris.isEmpty()) {
                throw new Exception("Missing software statement redirect URI.");
            }

            List<String> redirectUris = oidcClient.getRedirectUris();
            if (redirectUris == null || redirectUris.isEmpty()) {
                throw new Exception("Missing redirect URI.");
            }

            if (!ssaRedirectUris.containsAll(redirectUris)) {
                throw new Exception("[software_redirect_uris] not found in SSA.");
            }

            // valida as roles
            Object softwareRoles = token.getOtherClaims().get("software_roles");
            if (softwareRoles != null) {
                roles = (ArrayList) softwareRoles;
            } else {
                throw new Exception("[software_roles] not found in SSA.");
            }

            if (oidcClient.getScope() == null || oidcClient.getScope().trim().isEmpty()) {
                StringBuilder scope = new StringBuilder();

                if (roles.stream().anyMatch(x -> (x.equals(CONTA) || (x.equals(CCORR))))) {
                    scope.append("openid");
                }

                for (String role : roles) {
                    if (role.equals(DADOS)) {
                        scope.append(String.join(" ", DADOS_SCOPES));
                    }
                }

                scope.append(" ");

                // Define os scopes do client
                oidcClient.setScope(scope.toString());
            } else {
                List<String> allowedScopes = new ArrayList<>();

                logger.info(String.join(" ", roles));

                if (roles.stream().anyMatch(x -> x.equals(DADOS))) {
                    allowedScopes.addAll(DADOS_SCOPES);
                }

                String[] scopes = oidcClient.getScope().split(" ");

                if (!Arrays.stream(scopes).allMatch(allowedScopes::contains)) {
                    throw new Exception("[scopes] contains invalid options.");
                }
            }

            oidcClient.setTlsClientCertificateBoundAccessTokens(true);

            oidcClient.setRequestObjectSigningAlg(Algorithm.PS256);

            return new SoftwareStatement(
                    roles,
                    token.getOtherClaims().get("software_logo_uri").toString(),
                    token.getOtherClaims().get("org_id").toString()
            );
        } catch (Exception e) {
            logger.error(e);
            throw new ErrorResponseException(ErrorCodes.INVALID_CLIENT_METADATA, e.getMessage(),
                    Response.Status.BAD_REQUEST);
        }
    }
}

class SoftwareStatement {

    List<String> roles;

    String softwareLogoUri;

    String OrgId;

    public List<String> getRoles() {
        return roles;
    }

    public String getSoftwareLogoUri() {
        return softwareLogoUri;
    }

    public String getOrgId() {
        return OrgId;
    }

    public SoftwareStatement(List<String> roles, String softwareLogoUri, String orgId) {
        this.roles = roles;
        this.softwareLogoUri = softwareLogoUri;
        this.OrgId = orgId;
    }
}
