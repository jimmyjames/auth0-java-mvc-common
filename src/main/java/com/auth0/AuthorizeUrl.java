package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * Class to create and customize an Auth0 Authorize URL.
 * It's not reusable.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused", "SameParameterValue"})
public class AuthorizeUrl {

    private static final String SCOPE_OPENID = "openid";
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final AuthorizeUrlBuilder builder;
    private final String responseType;
    private boolean legacySameSiteCookie;
    private String nonce;
    private String state;

    private boolean used;

    /**
     * @param client       the Auth0 Authentication API client
     * @param request      request where the state will be saved
     * @param redirectUrl  the url to redirect to after authentication
     * @param responseType the response type to use
     */
    AuthorizeUrl(AuthAPI client, HttpServletRequest request, HttpServletResponse response, String redirectUrl, String responseType) {
//        this(client, request, response, redirectUrl, responseType, true);
        this.request = request;
        this.response = response;
        this.responseType = responseType;
        this.legacySameSiteCookie = true;
        this.builder = client.authorizeUrl(redirectUrl)
                .withResponseType(responseType)
                .withScope(SCOPE_OPENID);
    }
//
//    /**
//     * @param client       the Auth0 Authentication API client
//     * @param request      request where the state will be saved
//     * @param redirectUrl  the url to redirect to after authentication
//     * @param responseType the response type to use
//     */
//    AuthorizeUrl(AuthAPI client, HttpServletRequest request, HttpServletResponse response, String redirectUrl, String responseType, boolean legacySameSiteCookie) {
//        this.request = request;
//        this.response = response;
//        this.responseType = responseType;
//        this.legacySameSiteCookie = legacySameSiteCookie;
//        this.builder = client.authorizeUrl(redirectUrl)
//                .withResponseType(responseType)
//                .withScope(SCOPE_OPENID);
//    }

    /**
     * Sets the connection value.
     *
     * @param connection connection to set
     * @return the builder instance
     */
    public AuthorizeUrl withConnection(String connection) {
        builder.withConnection(connection);
        return this;
    }

    public AuthorizeUrl withLegacySameSiteCookie(boolean legacySameSiteCookie) {
        this.legacySameSiteCookie = legacySameSiteCookie;
        return this;
    }

    /**
     * Sets the audience value.
     *
     * @param audience audience to set
     * @return the builder instance
     */
    public AuthorizeUrl withAudience(String audience) {
        builder.withAudience(audience);
        return this;
    }

    /**
     * Sets the state value.
     *
     * @param state state to set
     * @return the builder instance
     */
    public AuthorizeUrl withState(String state) {
//        TransientCookieStore.storeState(response, state);
//        RandomStorage.setSessionState(request, response, state);
        this.state = state;
        builder.withState(state);
        return this;
    }

    /**
     * Sets the nonce value.
     *
     * @param nonce nonce to set
     * @return the builder instance
     */
    public AuthorizeUrl withNonce(String nonce) {
//        TransientCookieStore.storeNonce(response, nonce);
//        RandomStorage.setSessionNonce(request, response, nonce);
        this.nonce = nonce;
        builder.withParameter("nonce", nonce);
        return this;
    }

    /**
     * Sets the scope value.
     *
     * @param scope scope to set
     * @return the builder instance
     */
    public AuthorizeUrl withScope(String scope) {
        builder.withScope(scope);
        return this;
    }

    /**
     * Sets an additional parameter.
     *
     * @param name  name of the parameter
     * @param value value of the parameter to set
     * @return the builder instance
     */
    public AuthorizeUrl withParameter(String name, String value) {
        if ("state".equals(name) || "nonce".equals(name)) {
            throw new IllegalArgumentException("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
        }
        if ("response_type".equals(name)) {
            throw new IllegalArgumentException("Response type cannot be changed once set.");
        }
        if ("redirect_uri".equals(name)) {
            throw new IllegalArgumentException("Redirect URI cannot be changed once set.");
        }
        builder.withParameter(name, value);
        return this;
    }

    /**
     * Creates a string representation of the URL with the configured parameters.
     * It cannot be called more than once.
     *
     * @return the string URL
     * @throws IllegalStateException if it's called more than once
     */
    public String build() throws IllegalStateException {
        if (used) {
            throw new IllegalStateException("The AuthorizeUrl instance must not be reused.");
        }
        used = true;
        // TODO - how to determine what to do with cookies for sameSite and secure?
        // and fallback ;)
        // SameSite + Secure if:
        // -- responseType is id_token (contains, or exact? Probably contains since that is what determines response mode)
        // -- response mode is form_post (this is determined in request processor...)
//        List<String> responseTypes = Arrays.asList(responseType.split(" "));
        // UGH.... we don't have access to the state and nonce here...
//        boolean isSameSiteNone = containsFormPost();
//        TransientCookieStore.storeNonce(response, nonce, isSameSiteNone);
//        TransientCookieStore.storeState(response, state, isSameSiteNone);

        TransientCookieStore.SameSite sameSiteValue = containsFormPost() ? TransientCookieStore.SameSite.NONE : TransientCookieStore.SameSite.LAX;
        TransientCookieStore.storeState(response, state, sameSiteValue, legacySameSiteCookie);
        if (nonce != null) {
            TransientCookieStore.storeNonce(response, nonce, sameSiteValue, legacySameSiteCookie);
        }


//        if (containsFormPost()) {
//            TransientCookieStore.storeNonce(response, nonce, TransientCookieStore.SameSite.NONE, true);
//            TransientCookieStore.storeState(response, state, TransientCookieStore.SameSite.NONE, true);
//        } else {
//            TransientCookieStore.storeNonce(response, nonce, TransientCookieStore.SameSite.NONE, true);
//            TransientCookieStore.storeState(response, state, TransientCookieStore.SameSite.NONE, true);
//        }
        return builder.build();
    }

    private boolean containsFormPost() {
        List<String> responseTypes = Arrays.asList(responseType.split(" "));
        return responseTypes.contains("id_token");
    }

}
