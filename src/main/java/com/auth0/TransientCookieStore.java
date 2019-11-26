package com.auth0;

//import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class TransientCookieStore {

    private static final String STATE = "com.auth0.state.updated";
    private static final String NONCE = "com.auth0.nonce.updated";

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
        // TODO verify this is correct
        return new String(Base64.getUrlEncoder().encode(randomBytes));
//        return Base64.encodeBase64URLSafeString(randomBytes);
    }

    static void storeState(HttpServletResponse response, String state) {
        store(response, STATE, state);
    }

    static void storeNonce(HttpServletResponse response, String nonce) {
        store(response, NONCE, nonce);
    }

    static String getState(HttpServletRequest request, HttpServletResponse response) {
        return getOnce(STATE, request, response);
    }

    static String getNonce(HttpServletRequest request, HttpServletResponse response) {
        return getOnce(NONCE, request, response);
    }

    private static void store(HttpServletResponse response, String key, String value) {
        String cookie = String.format("%s=%s; HttpOnly; SameSite=None; Secure", key, value);
        response.addHeader("Set-Cookie", cookie);
    }

    private static String getOnce(String cookieName, HttpServletRequest request, HttpServletResponse response) {
        List<Cookie> cookies = Arrays.asList(request.getCookies());
        Cookie cookie = cookies.stream()
                .filter(c -> cookieName.equals(c.getName()))
                .findFirst()
                .orElse(null);

        String cookieVal = cookie == null ? null : cookie.getValue();

        delete(cookie, response);

        return cookieVal;
    }

    private static void delete(Cookie cookie, HttpServletResponse response) {
        if (cookie != null) {
            cookie.setMaxAge(0);
            cookie.setValue("");
            response.addCookie(cookie);
        }
    }
}
