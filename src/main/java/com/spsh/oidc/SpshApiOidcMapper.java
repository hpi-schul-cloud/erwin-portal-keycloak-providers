package com.spsh.oidc;

import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import com.spsh.util.ApiFetchHelper;

public class SpshApiOidcMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger LOGGER = Logger.getLogger(SpshApiOidcMapper.class);

    public static final String PROVIDER_ID = "spsh-custom-oidc-api-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String FETCH_URL_TOKEN = "fetchUrlToken";
    public static final String FETCH_URL_ROLE = "fetchUrlRole";
    public static final String TIMEOUT_MS = "timeoutMs";
    public static final String CACHE_TTL_SECONDS = "cacheTtlSeconds";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, SpshApiOidcMapper.class);
        OIDCAttributeMapperHelper.addJsonTypeConfig(configProperties);

        ProviderConfigProperty fetchUrlTokenProperty = new ProviderConfigProperty();
        fetchUrlTokenProperty.setName(FETCH_URL_TOKEN);
        fetchUrlTokenProperty.setLabel("Erwin Token Fetch Url");
        fetchUrlTokenProperty.setType(ProviderConfigProperty.STRING_TYPE);
        fetchUrlTokenProperty.setHelpText("The URL to fetch the token data from the Erwin Backend.");
        configProperties.add(fetchUrlTokenProperty);

        ProviderConfigProperty fetchUrlRoleProperty = new ProviderConfigProperty();
        fetchUrlRoleProperty.setName(FETCH_URL_ROLE);
        fetchUrlRoleProperty.setLabel("Erwin Role Fetch Url");
        fetchUrlRoleProperty.setType(ProviderConfigProperty.STRING_TYPE);
        fetchUrlRoleProperty.setHelpText("The URL to fetch the role data from the Erwin Backend.");
        configProperties.add(fetchUrlRoleProperty);

        ProviderConfigProperty timeoutMsProperty = new ProviderConfigProperty();
        timeoutMsProperty.setName(TIMEOUT_MS);
        timeoutMsProperty.setLabel("Fetch timeout ms");
        timeoutMsProperty.setType(ProviderConfigProperty.INTEGER_TYPE);
        timeoutMsProperty.setHelpText("The fetch timeout in milliseconds");
        timeoutMsProperty.setDefaultValue("1500");
        configProperties.add(timeoutMsProperty);

        ProviderConfigProperty cacheTtlProperty = new ProviderConfigProperty();
        cacheTtlProperty.setName(CACHE_TTL_SECONDS);
        cacheTtlProperty.setLabel("Cache TTL seconds");
        cacheTtlProperty.setType(ProviderConfigProperty.INTEGER_TYPE);
        cacheTtlProperty.setHelpText("The cache lifetime in seconds");
        cacheTtlProperty.setDefaultValue("60");
        configProperties.add(cacheTtlProperty);
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "ErWIn Custom OIDC Api Mapper";
    }

    @Override
    public String getHelpText() {
        return "The mapper calls the provided ErWIn-Portal fetch url, extracts the provided JsonPath from the api response and maps the result if not null to the claim";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        final var config = mappingModel.getConfig();

        final var fetchUrlToken = config.get(FETCH_URL_TOKEN);
        final var fetchUrlRole = config.get(FETCH_URL_ROLE);
        if (fetchUrlToken == null || fetchUrlRole == null) {
            LOGGER.warn("SpshApiOidcMapper: At least one fetchUrl is null. No data will be fetched, extracted and mapped.");
            throw new IllegalArgumentException("SpshApiOidcMapper: At least one fetchUrl is null. No data will be fetched, extracted and mapped.");
        }

        final int timeoutMs = Integer.parseInt(config.getOrDefault(TIMEOUT_MS, "1500"));
        final int cacheTtlSec = Integer.parseInt(config.getOrDefault(CACHE_TTL_SECONDS, "60"));

        final UserModel user = (userSession != null) ? userSession.getUser() : null;
        if (user == null) {
            return;
        }

        final var keycloakUserId = user.getId();
        if (keycloakUserId == null) {
            LOGGER.warn("SpshApiOidcMapper: keycloakUserId is null. No data will be fetched, extracted and mapped.");
            throw new IllegalArgumentException("SpshApiOidcMapper: keycloakUserId is null. No data will be fetched, extracted and mapped.");
        }
        LOGGER.info(String.format("Setting claims via custom SpshApiOidcMapper for userSub: %s", keycloakUserId));
        LOGGER.debug(String.format("Using fetchUrl: %s", fetchUrlToken));

        final var clientName = keycloakSession.getContext().getClient().getName();

        final var cacheTokenDataKey = "spsh_mapper_token_data_cache_" + mappingModel.getId();
        final var cacheRoleDataKey = "spsh_mapper_role_data_cache_" + mappingModel.getId();

        final var tokenData = getCachedOrFetch(userSession, cacheTtlSec, cacheTokenDataKey,
                () -> ApiFetchHelper.fetchApiData(fetchUrlToken, ApiFetchHelper.getTokenDataBody(keycloakUserId), timeoutMs))
                .orElseThrow(() -> new UnsupportedOperationException("Can't fetch token data"));

        final var roleData = getCachedOrFetch(userSession, cacheTtlSec, cacheRoleDataKey,
                () -> ApiFetchHelper.fetchApiData(fetchUrlRole, ApiFetchHelper.getRoleDataBody(keycloakUserId, clientName), timeoutMs))
                .orElse(null);

        mapClaimsToToken(token, tokenData, roleData);
    }

    private Optional<String> getCachedOrFetch(final UserSessionModel userSession, final int cacheTtlSec,
                                              final String key, ThrowingSupplier<String> supplier) {
        try {
            LOGGER.debug("retrieving info from cache if valid");

            final var cached = userSession.getNote(key);
            final var ts = userSession.getNote(key + "_ts");
            final var now = System.currentTimeMillis();

            if (cached != null && ts != null) {
                LOGGER.debug("cache found, testing validity");

                final var fetchedAt = Long.parseLong(ts);
                if ((now - fetchedAt) <= cacheTtlSec * 1000L) {
                    LOGGER.debug("cache valid, returning");

                    return Optional.of(cached);
                }
            }

            LOGGER.debug("no cache found");

            final var data = supplier.get();
            writeCacheInUserSession(userSession, key, data);

            return Optional.ofNullable(data);
        } catch (final Exception e) {
            LOGGER.error("Error in request, returning empty for '" + key + "'", e);
            return Optional.empty();
        }
    }

    private void writeCacheInUserSession(final UserSessionModel userSession, final String key, final String val) {
        try {
            userSession.setNote(key, val);
            userSession.setNote(key + "_ts", Long.toString(System.currentTimeMillis()));
        } catch (Exception e) {
            LOGGER.debug("Failed to write session cache with key: " + key, e);
        }
    }

    private static void mapClaimsToToken(final IDToken token, final String tokenData, final String roleData) {
        if (tokenData == null) {
            return;
        }

        try {
            final var tokenObj = new ObjectMapper().readTree(tokenData);

            final var person = tokenObj.get("personData");
            mapRoleData(person, roleData);

            final var schule = tokenObj.get("schuleData");
            final var klassen = tokenObj.get("klasseData");

            token.setOtherClaims("person", person);
            token.setOtherClaims("schule", schule);
            token.setOtherClaims("klassen", klassen);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Can't parse json from token data endpoint", e);
        }
    }

    private static void mapRoleData(JsonNode person, String roleData) throws JsonProcessingException {
        if (roleData != null) {
            final var roleObj = new ObjectMapper().readTree(roleData);

            final var role = roleObj.get("mapToLmsRolle");
            if (role != null) {
                ((ObjectNode) person).set("rolle", role);
            }
        }
    }

    private interface ThrowingSupplier<T> {

        T get() throws Exception;
    }
}