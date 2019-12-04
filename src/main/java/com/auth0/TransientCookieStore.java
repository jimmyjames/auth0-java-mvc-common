package com.auth0;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class TransientCookieStore {

    enum SameSite {
        LAX("Lax"),
        NONE("None"),
        STRICT("Strict");

        private String value;

//        public String getValue() {
//            return this.value;
//        }

        SameSite(String value) {
            this.value = value;
        }
    }

    private SameSite sameSite;
    private boolean isSecure;

    private static final String STATE = "com.auth0.state.updated";
    private static final String NONCE = "com.auth0.nonce.updated";
//
//    SameSite getSameSite() {
//        return this.sameSite;
//    }
//
//    void setSameSite(SameSite sameSite) {
//        this.sameSite = sameSite;
//    }
//
//    boolean isSecure() {
//        return this.isSecure;
//    }
//
//    void setSecure(boolean isSecure) {
//        this.isSecure = isSecure;
//    }

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
    }


    static void storeState(HttpServletResponse response, String state, SameSite sameSite, boolean legacySameSiteCookie) {
        store(response, STATE, state, sameSite, legacySameSiteCookie);
    }

    static void storeNonce(HttpServletResponse response, String nonce, SameSite sameSite, boolean legacySameSiteCookie) {
        store(response, NONCE, nonce, sameSite, legacySameSiteCookie);
    }

    static String getState(HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        return getOnce(STATE, request, response, legacySameSiteCookie);
    }

    static String getNonce(HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        return getOnce(NONCE, request, response, legacySameSiteCookie);
    }

    private static void store(HttpServletResponse response, String key, String value, SameSite sameSite, boolean legacySameSiteCookie) {
        boolean sameSiteNone = SameSite.NONE.equals(sameSite);

        String cookie = String.format("%s=%s; HttpOnly; SameSite=%s", key, value, sameSite);
        if (sameSiteNone) {
            cookie = cookie.concat("; Secure");
        }
        response.addHeader("Set-Cookie", cookie);

        // set legacy fallback cookie (if configured) for clients that won't accept SameSite=None
        if (sameSiteNone && legacySameSiteCookie) {
            String legacyCookie = String.format("%s=%s; HttpOnly", "_" + key, value);
            response.addHeader("Set-Cookie", legacyCookie);
        }

    }

    private static String getOnce(String cookieName, HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        List<Cookie> cookies = Arrays.asList(request.getCookies());
        Cookie cookie = cookies.stream()
                .filter(c -> cookieName.equals(c.getName()))
                .findFirst()
                .orElse(null);

        String cookieVal = cookie == null ? null : cookie.getValue();

        delete(cookie, response);

        if (legacySameSiteCookie) {
            Cookie legacyCookie = cookies.stream()
                    .filter(c -> ("_" + cookieName).equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            String legacyCookieVal = legacyCookie == null ? null : legacyCookie.getValue();

            cookieVal = cookieVal == null ? legacyCookieVal : cookieVal;
            delete(legacyCookie, response);
        }

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
