package com.auth0;

import org.hamcrest.beans.HasPropertyWithValue;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.Cookie;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

public class TransientCookieStoreTest {

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldGetRandomString() {
        String string = RandomStorage.secureRandomString();
        Assert.assertThat(string, is(notNullValue()));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", TransientCookieStore.SameSite.NONE, true);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers.contains("com.auth0.state=123456; HttpOnly; SameSite=None; Secure"), is(true));
        assertThat(headers.contains("_com.auth0.state=123456; HttpOnly"), is(true));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", TransientCookieStore.SameSite.NONE, false);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.contains("com.auth0.state=123456; HttpOnly; SameSite=None; Secure"), is(true));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", TransientCookieStore.SameSite.NONE, true);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers.contains("com.auth0.nonce=123456; HttpOnly; SameSite=None; Secure"), is(true));
        assertThat(headers.contains("_com.auth0.nonce=123456; HttpOnly"), is(true));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", TransientCookieStore.SameSite.NONE, false);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.contains("com.auth0.nonce=123456; HttpOnly; SameSite=None; Secure"), is(true));
    }

    @Test
    public void shouldRemoveStateSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.state", "123456");

        request.setCookies(cookie1, cookie2);

        String state = TransientCookieStore.getState(request, response, true).get();
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(2));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.nonce", "123456");

        request.setCookies(cookie1, cookie2);

        String state = TransientCookieStore.getNonce(request, response, true).get();
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(2));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldReturnEmptyStateWhenNoCookies() {
        Optional<String> state = TransientCookieStore.getState(request, response, true);
        assertThat(state.isPresent(), is(false));
    }

    @Test
    public void shouldReturnEmptyNonceWhenNoCookies() {
        Optional<String> nonce = TransientCookieStore.getNonce(request, response, true);
        assertThat(nonce.isPresent(), is(false));
    }

    @Test
    public void shouldReturnEmptyWhenNoStateCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        Optional<String> state = TransientCookieStore.getState(request, response, true);
        assertThat(state.isPresent(), is(false));
    }

    @Test
    public void shouldReturnEmptyWhenNoNonceCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        Optional<String> nonce = TransientCookieStore.getNonce(request, response, true);
        assertThat(nonce.isPresent(), is(false));
        assertThat(nonce.isPresent(), is(false));
    }
//    @Test
//    public void shouldAcceptBothNullStates() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//        boolean validState = RandomStorage.checkSessionState(req, null);
//        assertThat(validState, is(true));
//    }
//
//    @Test
//    public void shouldCheckAndRemoveInvalidState() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//        req.getSession().setAttribute("com.auth0.state", "123456");
//
//        boolean validState = RandomStorage.checkSessionState(req, "abcdef");
//        assertThat(validState, is(false));
//        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
//    }
//
//    @Test
//    public void shouldCheckAndRemoveCorrectState() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//        req.getSession().setAttribute("com.auth0.state", "123456");
//
//        boolean validState = RandomStorage.checkSessionState(req, "123456");
//        assertThat(validState, is(true));
//        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
//    }
//
//    @Test
//    public void shouldSetNonce() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//
//        RandomStorage.setSessionNonce(req, "123456");
//        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is("123456"));
//    }
//
//    @Test
//    public void shouldGetAndRemoveNonce() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//        req.getSession().setAttribute("com.auth0.nonce", "123456");
//
//        String nonce = RandomStorage.removeSessionNonce(req);
//        assertThat(nonce, is("123456"));
//        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
//    }
//
//    @Test
//    public void shouldGetAndRemoveNonceIfMissing() {
//        MockHttpServletRequest req = new MockHttpServletRequest();
//
//        String nonce = RandomStorage.removeSessionNonce(req);
//        assertThat(nonce, is(nullValue()));
//        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
//    }
}