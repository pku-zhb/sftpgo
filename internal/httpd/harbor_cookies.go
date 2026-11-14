// Copyright (C) 2026 Harbor Drive contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const maxWebClientCookieMinutes = 31 * 24 * 60

func configureWebClientCookieDuration(minutes int) error {
	if minutes < 0 || minutes > maxWebClientCookieMinutes {
		return fmt.Errorf("web_client_cookie_lifetime must be between 0 and %d minutes", maxWebClientCookieMinutes)
	}
	webClientCookieDuration = time.Duration(minutes) * time.Minute
	return nil
}

// A saved login URL must not replace an authenticated cookie with a WebLogin
// CSRF cookie. Only a fully verified WebClient session may bypass the form.
func (s *httpdServer) redirectAuthenticatedWebClient(w http.ResponseWriter, r *http.Request) bool {
	claims, err := jwt.VerifyRequest(s.tokenAuth, r, jwt.TokenFromCookie)
	if err != nil || !claims.Audience.Contains(tokenAudienceWebClient) {
		return false
	}
	r = r.WithContext(jwt.NewContext(r.Context(), claims, nil))
	if isTokenInvalidated(r) || validateIPForToken(claims, util.GetIPFromRemoteAddress(r.RemoteAddr)) != nil ||
		checkTokenSignature(r, claims) != nil {
		return false
	}
	target, ok := safeRedirectTarget(r.URL.Query().Get("next"), webClientFilesPath)
	if !ok {
		target = webClientFilesPath
	}
	http.Redirect(w, r, target, http.StatusFound)
	return true
}
