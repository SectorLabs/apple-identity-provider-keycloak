package at.klausbetz.provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorResponseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AppleIdentityProviderTest {

    private static final String ID_TOKEN = "apple-id-token";
    private static final String SERVICES_ID = "com.example.web";
    private static final String BUNDLE_ID = "com.example.ios";
    private static final String THIRD_PARTY_BUNDLE_ID = "com.thirdparty.ios";

    private EventBuilder event;
    private TestProvider provider;
    private boolean enforce;
    private String[] tokenAudience;

    class TestProvider extends AppleIdentityProvider {
        TestProvider(AppleIdentityProviderConfig config) {
            super(mock(KeycloakSession.class), config);
        }

        @Override
        protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
            assertEquals(ID_TOKEN, encodedToken);
            JsonWebToken token = new JsonWebToken();
            token.subject("apple-user");
            token.audience(tokenAudience);
            return token;
        }

        @Override
        protected boolean isIdTokenAudienceEnforced() {
            return enforce;
        }
    }

    @BeforeEach
    void setup() {
        AppleIdentityProviderConfig config = new AppleIdentityProviderConfig(new IdentityProviderModel());
        config.setAlias("apple");
        config.setClientId(SERVICES_ID);
        config.getConfig().put(AppleIdentityProvider.ADDITIONAL_AUDIENCES_CONFIG, "com.example.other##" + BUNDLE_ID);

        provider = new TestProvider(config);
        event = mock(EventBuilder.class);
        enforce = true;
    }

    private BrokeredIdentityContext exchangeIdToken() {
        return provider.exchangeExternalImpl(event, new MultivaluedMapBuilder().subjectToken(ID_TOKEN).subjectTokenType(OAuth2Constants.ID_TOKEN_TYPE).build());
    }

    @Test
    void givenIdTokenIssuedToConfiguredClient_whenExchanging_thenIdentityIsReturned() {
        tokenAudience = new String[]{SERVICES_ID};

        assertEquals("apple-user", exchangeIdToken().getId());
    }

    @Test
    void givenIdTokenIssuedToAdditionalAudience_whenExchanging_thenIdentityIsReturned() {
        tokenAudience = new String[]{BUNDLE_ID};

        assertEquals("apple-user", exchangeIdToken().getId());
    }

    @Test
    void givenIdTokenIssuedToThirdPartyApp_whenExchanging_thenTokenIsRejected() {
        tokenAudience = new String[]{THIRD_PARTY_BUNDLE_ID};

        assertThrows(ErrorResponseException.class, this::exchangeIdToken);
        verify(event).detail(Details.REASON, "token audience mismatch");
        verify(event).detail("token_audience", THIRD_PARTY_BUNDLE_ID);
    }

    @Test
    void givenIdTokenWithoutAudience_whenExchanging_thenTokenIsRejected() {
        tokenAudience = null;

        assertThrows(ErrorResponseException.class, this::exchangeIdToken);
        verify(event).detail(Details.REASON, "token audience mismatch");
    }

    @Test
    void givenIdTokenIssuedToThirdPartyAppAndEnforcementDisabled_whenExchanging_thenIdentityIsReturned() {
        enforce = false;
        tokenAudience = new String[]{THIRD_PARTY_BUNDLE_ID};

        assertEquals("apple-user", exchangeIdToken().getId());
        verify(event, never()).error(anyString());
    }

    @Test
    void givenEnforcementEnvVarUnset_whenCheckingEnforcement_thenItIsDisabled() {
        AppleIdentityProvider realProvider = new AppleIdentityProvider(mock(KeycloakSession.class), new AppleIdentityProviderConfig(new IdentityProviderModel()));

        assertFalse(realProvider.isIdTokenAudienceEnforced());
    }
}
