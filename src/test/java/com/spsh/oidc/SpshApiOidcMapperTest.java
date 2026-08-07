package com.spsh.oidc;

import com.spsh.oidc.dto.FetchUrlResponse;
import com.spsh.util.ApiFetchHelper;
import com.spsh.util.JsonHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.spsh.oidc.SpshApiOidcMapper.*;
import static org.junit.Assert.*;
import static org.keycloak.protocol.ProtocolMapperUtils.MULTIVALUED;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SpshApiOidcMapperTest {

    // expose protected setClaim
    static class TestableSpshApiOidcMapper extends SpshApiOidcMapper {
        public void callSetClaim(IDToken token,
                                 ProtocolMapperModel mappingModel,
                                 UserSessionModel userSession,
                                 KeycloakSession keycloakSession,
                                 ClientSessionContext clientSessionCtx) {
            super.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        }
    }

    private final TestableSpshApiOidcMapper mapper = new TestableSpshApiOidcMapper();

    @Mock
    ProtocolMapperModel mappingModel;
    @Mock
    UserSessionModel userSession;
    @Mock
    KeycloakSession keycloakSession;
    @Mock
    ClientSessionContext clientSessionCtx;
    @Mock
    AuthenticatedClientSessionModel clientSession;
    @Mock
    ClientModel clientModel;
    @Mock
    UserModel user;
    @Mock
    RoleModel roleModel;
    @Mock
    FetchUrlResponse fetchUrlResponse;

    private Map<String, String> baseConfig() {
        Map<String, String> config = new HashMap<>();
        config.put(FETCH_URL_TOKEN, "https://example.com/apiToken");
        config.put(FETCH_URL_ROLE, "https://example.com/apiRole");
        config.put(MULTIVALUED, "false");
        config.put(TIMEOUT_MS, "1500");
        config.put(CACHE_TTL_SECONDS, "60");
        return config;
    }

    private void setupCommonMocks(Map<String, String> config) {
        when(mappingModel.getConfig()).thenReturn(config);
        when(mappingModel.getId()).thenReturn("mapper-id");

        when(userSession.getUser()).thenReturn(user);
        when(user.getId()).thenReturn("user-123");

        final var context = mock(KeycloakContext.class);
        when(keycloakSession.getContext()).thenReturn(context);

        final var clientModel = mock(ClientModel.class);
        when(context.getClient()).thenReturn(clientModel);

        when(clientModel.getName()).thenReturn("ClientName");
    }

    @Test
    public void getDisplayCategory_returnsTokenMapper() {
        assertEquals("Token Mapper", mapper.getDisplayCategory());
    }

    @Test
    public void getDisplayType_returnsCustomDisplay() {
        assertEquals("ErWIn Custom OIDC Api Mapper", mapper.getDisplayType());
    }

    @Test
    public void getHelpText_notNull() {
        assertNotNull(mapper.getHelpText());
    }

    @Test
    public void getId_returnsProviderId() {
        assertEquals(PROVIDER_ID, mapper.getId());
    }

    @Test
    public void getConfigProperties_notEmpty() {
        List<ProviderConfigProperty> props = mapper.getConfigProperties();
        assertFalse(props.isEmpty());
    }

    @Test
    public void setClaim_userNull_doesNothing() {
        Map<String, String> config = baseConfig();
        when(mappingModel.getConfig()).thenReturn(config);
        when(userSession.getUser()).thenReturn(null);

        mapper.callSetClaim(new IDToken(), mappingModel, userSession, keycloakSession, clientSessionCtx);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setClaim_fetchUrlNull_throwsNotFoundException() {
        Map<String, String> config = baseConfig();
        config.remove(FETCH_URL_TOKEN);
        setupCommonMocks(config);

        mapper.callSetClaim(new IDToken(), mappingModel, userSession, keycloakSession, clientSessionCtx);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setClaim_userIdNull_throwsNotFoundException() {
        Map<String, String> config = baseConfig();
        setupCommonMocks(config);
        when(user.getId()).thenReturn(null);

        mapper.callSetClaim(new IDToken(), mappingModel, userSession, keycloakSession, clientSessionCtx);
    }

    @Test
    public void setClaim_validCache_usesCachedNoBackendCall() {
        Map<String, String> config = baseConfig();
        setupCommonMocks(config);

        when(userSession.getNote("spsh_mapper_token_data_cache_mapper-id"))
                .thenReturn("{\"some\":\"json\"}");
        when(userSession.getNote("spsh_mapper_token_data_cache_mapper-id_ts"))
                .thenReturn(Long.toString(System.currentTimeMillis()));

        try (MockedStatic<JsonHelper> jsonHelperMock = mockStatic(JsonHelper.class);
             MockedStatic<ApiFetchHelper> apiFetchMock = mockStatic(ApiFetchHelper.class)) {

            jsonHelperMock.when(() -> JsonHelper.isPathExisting(anyString(), anyString()))
                    .thenReturn(true);
            jsonHelperMock.when(() -> JsonHelper.extractFromJson(anyString()))
                    .thenReturn(fetchUrlResponse);

            IDToken token = mock(IDToken.class);

            mapper.callSetClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

            apiFetchMock.verify(() -> ApiFetchHelper.fetchApiData(anyString(), anyString(), anyInt()), Mockito.never());

            verify(token).setOtherClaims(eq("person"), any());
            verify(token).setOtherClaims(eq("schule"), any());
            verify(token).setOtherClaims(eq("klassen"), any());
        }
    }

    @Test
    public void setClaim_noCache_callsBackend_assignsRole_mapsClaim() {
        Map<String, String> config = baseConfig();
        setupCommonMocks(config);

        when(userSession.getNote(anyString())).thenReturn(null);

        try (MockedStatic<JsonHelper> jsonHelperMock = mockStatic(JsonHelper.class);
             MockedStatic<ApiFetchHelper> apiFetchMock = mockStatic(ApiFetchHelper.class)) {

            jsonHelperMock.when(() -> JsonHelper.isPathExisting(anyString(), anyString()))
                    .thenReturn(true);
            jsonHelperMock.when(() -> JsonHelper.extractFromJson(anyString()))
                    .thenReturn(fetchUrlResponse);

            apiFetchMock.when(() -> ApiFetchHelper.fetchApiData(anyString(), anyString(), anyInt()))
                    .thenReturn("{\"ok\":true}");


            apiFetchMock.when(() -> ApiFetchHelper.getTokenDataBody(anyString())).thenCallRealMethod();
            apiFetchMock.when(() -> ApiFetchHelper.getRoleDataBody(anyString(), anyString())).thenCallRealMethod();

            IDToken token = mock(IDToken.class);
            mapper.callSetClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);

           apiFetchMock.verify(() -> ApiFetchHelper.fetchApiData(
                   eq("https://example.com/apiToken"),
                   eq("{\"keycloakUserId\":\"user-123\"}"),
                   eq(1500)));

            verify(token).setOtherClaims(eq("person"), any());
            verify(token).setOtherClaims(eq("schule"), any());
            verify(token).setOtherClaims(eq("klassen"), any());

            verify(userSession).setNote(eq("spsh_mapper_token_data_cache_mapper-id"), anyString());
            verify(userSession).setNote(eq("spsh_mapper_token_data_cache_mapper-id_ts"), anyString());
        }
    }
}
