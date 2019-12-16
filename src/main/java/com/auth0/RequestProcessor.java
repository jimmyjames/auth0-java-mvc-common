package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.Validate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.auth0.InvalidRequestException.*;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 * When the tokens are obtained, it will request the user id associated to them and save it in the {@link javax.servlet.http.HttpSession}.
 */
class RequestProcessor {

    private static final String KEY_STATE = "state";
    private static final String KEY_ERROR = "error";
    private static final String KEY_ERROR_DESCRIPTION = "error_description";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_CODE = "code";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_RESPONSE_MODE = "response_mode";
    private static final String KEY_FORM_POST = "form_post";
    private static final String KEY_MAX_AGE = "max_age";

    // Visible for testing
    final IdTokenVerifier.Options verifyOptions;
    private final String responseType;
    private final AuthAPI client;
    private final IdTokenVerifier tokenVerifier;
    private final boolean legacySameSiteCookie;

    @VisibleForTesting
    RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions, IdTokenVerifier tokenVerifier, boolean legacySameSiteCookie) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        Validate.notNull(verifyOptions);
        this.client = client;
        this.responseType = responseType;
        this.verifyOptions = verifyOptions;
        this.tokenVerifier = tokenVerifier;
        this.legacySameSiteCookie = legacySameSiteCookie;
    }


    RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions) {
        this(client, responseType, verifyOptions, true);
    }

    RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions, boolean legacySameSiteCookie) {
        this(client, responseType, verifyOptions, new IdTokenVerifier(), legacySameSiteCookie);
    }

    /**
     * Getter for the AuthAPI client instance.
     * Used to customize options such as Telemetry and Logging.
     *
     * @return the AuthAPI client.
     */
    AuthAPI getClient() {
        return client;
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI, state and nonce parameters.
     *
     * @param response    the response, used to set auth-based cookies.
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter customization.
     */
    AuthorizeUrl buildAuthorizeUrl(HttpServletResponse response, String redirectUri, String state, String nonce) {
        AuthorizeUrl creator = new AuthorizeUrl(client, response, redirectUri, responseType)
                .withState(state)
                .withLegacySameSiteCookie(legacySameSiteCookie);

        List<String> responseTypeList = getResponseType();
        if (responseTypeList.contains(KEY_ID_TOKEN) && nonce != null) {
            creator.withNonce(nonce);
        }
        if (responseTypeList.contains(KEY_TOKEN) || responseTypeList.contains(KEY_ID_TOKEN)) {
            creator.withParameter(KEY_RESPONSE_MODE, KEY_FORM_POST);
        }
        if (verifyOptions.getMaxAge() != null) {
            creator.withParameter(KEY_MAX_AGE, verifyOptions.getMaxAge().toString());
        }
        return creator;
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request.
     * 2). Exchanging the authorization code received with this HTTP request for Auth0 tokens.
     * 3). Validating the ID Token.
     * 4). Clearing the stored state, nonce and max_age values.
     * 5). Handling success and any failure outcomes.
     *
     * @throws IdentityVerificationException if an error occurred while processing the request
     */
    Tokens process(HttpServletRequest req, HttpServletResponse response) throws IdentityVerificationException {
        assertNoError(req);
        assertValidState(req, response);

        Tokens frontChannelTokens = getFrontChannelTokens(req);
        List<String> responseTypeList = getResponseType();

        if (responseTypeList.contains(KEY_ID_TOKEN) && frontChannelTokens.getIdToken() == null) {
            throw new InvalidRequestException(MISSING_ID_TOKEN, "ID Token is missing from the response.");
        }
        if (responseTypeList.contains(KEY_TOKEN) && frontChannelTokens.getAccessToken() == null) {
            throw new InvalidRequestException(MISSING_ACCESS_TOKEN, "Access Token is missing from the response.");
        }

        // Nonce dynamically set and changes on every request.
        TransientCookieStore
                .getNonce(req, response, legacySameSiteCookie)
                .ifPresent(verifyOptions::setNonce);

        return getVerifiedTokens(req, frontChannelTokens, responseTypeList);
    }

    /**
     * Obtains code request tokens (if using Code flow) and validates the ID token.
     * @param req the HTTP request
     * @param frontChannelTokens the tokens obtained from the front channel
     * @param responseTypeList the reponse types
     * @return a Tokens object that wraps the values obtained from the front-channel and/or the code request response.
     * @throws IdentityVerificationException
     */
    private Tokens getVerifiedTokens(HttpServletRequest req, Tokens frontChannelTokens, List<String> responseTypeList)
            throws IdentityVerificationException {

        String authorizationCode = req.getParameter(KEY_CODE);
        Tokens codeExchangeTokens = null;

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                // Implicit/Hybrid flow: must verify front-channel ID Token first
                tokenVerifier.verify(frontChannelTokens.getIdToken(), verifyOptions);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                // Code/Hybrid flow
                String redirectUri = req.getRequestURL().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    // If we already verified the front-channel token, don't verify it again.
                    String idTokenFromCodeExchange = codeExchangeTokens.getIdToken();
                    if (idTokenFromCodeExchange != null) {
                        tokenVerifier.verify(idTokenFromCodeExchange, verifyOptions);
                    }
                }
            }
        } catch (TokenValidationException e) {
            throw new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the ID Token.", e);
        } catch (Auth0Exception e) {
            throw new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the authorization code.", e);
        }
        // Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.trim().split("\\s+"));
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit or Hybrid Grant.
     *
     * @param req the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens getFrontChannelTokens(HttpServletRequest req) {
        Long expiresIn = req.getParameter(KEY_EXPIRES_IN) == null ? null : Long.parseLong(req.getParameter(KEY_EXPIRES_IN));
        return new Tokens(req.getParameter(KEY_ACCESS_TOKEN), req.getParameter(KEY_ID_TOKEN), null, req.getParameter(KEY_TOKEN_TYPE), expiresIn);
    }

    /**
     * Checks for the presence of an error in the request parameters
     *
     * @param req the request
     * @throws InvalidRequestException if the request contains an error
     */
    private void assertNoError(HttpServletRequest req) throws InvalidRequestException {
        String error = req.getParameter(KEY_ERROR);
        if (error != null) {
            String errorDescription = req.getParameter(KEY_ERROR_DESCRIPTION);
            throw new InvalidRequestException(error, errorDescription);
        }
    }

    /**
     * Checks whether the state persisted in the session matches the state value received in the request parameters.
     *
     * @param req the request
     * @throws InvalidRequestException if the request contains a different state from the expected one
     */
    private void assertValidState(HttpServletRequest req, HttpServletResponse response) throws InvalidRequestException {
        String stateFromRequest = req.getParameter(KEY_STATE);
        Optional<String> actualState = TransientCookieStore.getState(req, response, legacySameSiteCookie);

        if (!actualState.isPresent() || !stateFromRequest.equals(actualState.get())) {
            throw new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one.");
        }
    }

    /**
     * Calls the Auth0 Authentication API to perform a Code Exchange.
     *
     * @param authorizationCode the code received on the login response.
     * @param redirectUri       the redirect uri used on login request.
     * @return a new instance of {@link Tokens} with the received credentials.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#exchangeCode(String, String)
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        TokenHolder holder = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }

    /**
     * Used to keep the best version of each token.
     * It will prioritize the ID Token received in the front-channel, and the Access Token received in the code exchange request.
     *
     * @param frontChannelTokens the front-channel obtained tokens.
     * @param codeExchangeTokens the code-exchange obtained tokens.
     * @return a merged version of Tokens using the best tokens when possible.
     */
    private Tokens mergeTokens(Tokens frontChannelTokens, Tokens codeExchangeTokens) {
        if (codeExchangeTokens == null) {
            return frontChannelTokens;
        }

        // Prefer access token from the code exchange
        String accessToken;
        String type;
        Long expiresIn;

        if (codeExchangeTokens.getAccessToken() != null) {
            accessToken = codeExchangeTokens.getAccessToken();
            type = codeExchangeTokens.getType();
            expiresIn = codeExchangeTokens.getExpiresIn();
        } else {
            accessToken = frontChannelTokens.getAccessToken();
            type = frontChannelTokens.getType();
            expiresIn = frontChannelTokens.getExpiresIn();
        }

        // Prefer ID token from the front-channel
        String idToken = frontChannelTokens.getIdToken() != null ? frontChannelTokens.getIdToken() : codeExchangeTokens.getIdToken();

        // Refresh token only available from the code exchange
        String refreshToken = codeExchangeTokens.getRefreshToken();

        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

}