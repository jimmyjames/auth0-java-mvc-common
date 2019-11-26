package com.auth0;

import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

// TODO - DELETE!! Use cookieStorage instead
class RandomStorage extends SessionUtils {

    private static final String SESSION_STATE = "com.auth0.state";
    private static final String SESSION_NONCE = "com.auth0.nonce";

    /**
     * Generates a new random string using {@link SecureRandom}.
     * The output can be used as State or Nonce values for API requests.
     *
     * @return a new random string.
     */
    static String secureRandomString() {
        final SecureRandom sr = new SecureRandom();
        final byte[] randomBytes = new byte[32];
        sr.nextBytes(randomBytes);
        return Base64.encodeBase64URLSafeString(randomBytes);
    }

    /**
     * Check's if the request {@link HttpSession} saved state is equal to the given state.
     * After the check, the value will be removed from the session.
     *
     * @param req   the request
     * @param state the state value to compare against.
     * @return whether the state matches the expected one or not.
     */
    static boolean checkSessionState(HttpServletRequest req, HttpServletResponse response, String state) {
        List<Cookie> cookies = Arrays.asList(req.getCookies());
        for (Cookie cookie : cookies) {
            if (SESSION_STATE.equals(cookie.getName())) {
                // TODO remove cookie?
                boolean isOk = cookie.getValue().equals(state);
                cookie.setMaxAge(0);
                cookie.setValue("");
                response.addCookie(cookie);
                return isOk;
//                return cookie.getValue().equals(state);
            }
        }
        return false;
//        String currentState = (String) remove(req, SESSION_STATE);
//        return (currentState == null && state == null) || currentState != null && currentState.equals(state);
    }

    /**
     * Saves the given state in the request {@link HttpSession}.
     * If a state is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param state the state value to set.
     */
    static void setSessionState(HttpServletRequest req, HttpServletResponse response, String state) {
//        Cookie cookie = new Cookie(SESSION_STATE, state);
        String cookie = String.format("%s=%s; HttpOnly; SameSite=None; Secure", SESSION_STATE, state);
        response.addHeader("Set-Cookie", cookie);
//        req.getCookies()
//        set(req, SESSION_STATE, state);
    }

    /**
     * Saves the given nonce in the request {@link HttpSession}.
     * If a nonce is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param nonce the nonce value to set.
     */
    static void setSessionNonce(HttpServletRequest req, HttpServletResponse response, String nonce) {
        String cookie = String.format("%s=%s; HttpOnly; SameSite=None; Secure", SESSION_NONCE, nonce);
        response.addHeader("Set-Cookie", cookie);
//        set(req, SESSION_NONCE, nonce);
    }

    /**
     * Removes the nonce present in the request {@link HttpSession} and then returns it.
     *
     * @param req the HTTP Servlet request.
     * @return the nonce value or null if it was not set.
     */
    static String removeSessionNonce(HttpServletRequest req, HttpServletResponse response) {
        List<Cookie> cookies = Arrays.asList(req.getCookies());
        for (Cookie cookie : cookies) {
            if (SESSION_NONCE.equals(cookie.getName())) {
                // TODO remove nonce value?
                String nonceValue = cookie.getValue();
                cookie.setMaxAge(0);
                cookie.setValue("");
                response.addCookie(cookie);
                return nonceValue;
//                return cookie.getValue();
            }
        }
        return null;
//        return (String) remove(req, SESSION_NONCE);
    }
}
