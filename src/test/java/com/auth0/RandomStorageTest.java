package com.auth0;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.Cookie;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class RandomStorageTest {

    @Test
    public void shouldGetRandomString() {
        String string = RandomStorage.secureRandomString();
        Assert.assertThat(string, is(notNullValue()));
    }

    @Test
    public void shouldSetState() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        TransientCookieStore.storeState(response, "123456", TransientCookieStore.SameSite.NONE, true);

        // TODO - since we are setting cookie via Set-Cookie header, this will be null
        // Should we just inspect the Set-Cookie header?
        Cookie state = response.getCookie("com.auth0.state.updated");
        assertThat(state.getValue(), is("123456"));

//        RandomStorage.setSessionState(req, "123456");
//        assertThat(req.getSession().getAttribute("com.auth0.state"), is("123456"));
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