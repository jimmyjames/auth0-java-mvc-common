package com.auth0;

import com.auth0.client.auth.AuthAPI;
import okhttp3.HttpUrl;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Collection;
import java.util.Enumeration;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class AuthorizeUrlTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private AuthAPI client;
    private HttpServletRequest request;
    private HttpServletResponse response;

    @Before
    public void setUp() {
        client = new AuthAPI("domain.auth0.com", "clientId", "clientSecret");
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldBuildValidStringUrl() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(url, is(notNullValue()));
        assertThat(HttpUrl.parse(url), is(notNullValue()));
    }

    @Test
    public void shouldSetDefaultScope() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid"));
    }

    @Test
    public void shouldSetResponseType() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("response_type"), is("id_token token"));
    }

    @Test
    public void shouldSetRedirectUrl() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("redirect_uri"), is("https://redirect.to/me"));
    }

    @Test
    public void shouldSetConnection() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withConnection("facebook")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("connection"), is("facebook"));
    }

    @Test
    public void shouldSetAudience() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withAudience("https://api.auth0.com/")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("audience"), is("https://api.auth0.com/"));
    }

    @Test
    public void shouldSetNonceSameSiteAndLegacyCookieByDefault() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withNonce("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers.contains("com.auth0.nonce=asdfghjkl; HttpOnly; SameSite=None; Secure"), is(true));
        assertThat(headers.contains("_com.auth0.nonce=asdfghjkl; HttpOnly"), is(true));
    }

    @Test
    public void shouldSetNonceSameSiteAndNotLegacyCookieWhenConfigured() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withNonce("asdfghjkl")
                .withLegacySameSiteCookie(false)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        assertThat(headers.contains("com.auth0.nonce=asdfghjkl; HttpOnly; SameSite=None; Secure"), is(true));
    }

    @Test
    public void shouldSetStateSameSiteAndLegacyCookieByDefault() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers.contains("com.auth0.state=asdfghjkl; HttpOnly; SameSite=None; Secure"), is(true));
        assertThat(headers.contains("_com.auth0.state=asdfghjkl; HttpOnly"), is(true));
    }

    @Test
    public void shouldSetStateSameSiteAndNotLegacyCookieWhenConfigured() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .withLegacySameSiteCookie(false)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        assertThat(headers.contains("com.auth0.state=asdfghjkl; HttpOnly; SameSite=None; Secure"), is(true));
    }

    @Test
    public void shouldSetNoCookiesWhenNonceAndStateNotSet() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), nullValue());
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), nullValue());

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

//    @Test
//    public void shouldSetStateAndSaveTheValueOnTheRequestSession() {
////        HttpServletRequest req = new MockHttpServletRequest();
//        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
//                .withState("asdfghjkl")
//                .build();
//        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));
//        String savedState = (String) request.getSession(true).getAttribute("com.auth0.state");
//        assertThat(savedState, is("asdfghjkl"));
//    }

    @Test
    public void shouldSetScope() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withScope("openid profile email")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid profile email"));
    }

    @Test
    public void shouldSetCustomParameterScope() {
//        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("custom", "value")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("custom"), is("value"));
    }

    @Test
    public void shouldThrowWhenReusingTheInstance() {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("The AuthorizeUrl instance must not be reused.");
//        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token");
        String firstCall = builder.build();
        assertThat(firstCall, is(notNullValue()));
        builder.build();
    }

    @Test
    public void shouldThrowWhenChangingTheRedirectURI() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Redirect URI cannot be changed once set.");
//        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("redirect_uri", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheResponseType() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response type cannot be changed once set.");
//        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("response_type", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheStateUsingCustomParameterSetter() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
//        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("state", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheNonceUsingCustomParameterSetter() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
//        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("nonce", "new_value");
    }
}