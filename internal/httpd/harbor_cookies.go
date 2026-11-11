// Copyright (C) 2026 Harbor Drive contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpd

import (
	"fmt"
	"time"
)

const maxWebClientCookieMinutes = 31 * 24 * 60

func configureWebClientCookieDuration(minutes int) error {
	if minutes < 0 || minutes > maxWebClientCookieMinutes {
		return fmt.Errorf("web_client_cookie_lifetime must be between 0 and %d minutes", maxWebClientCookieMinutes)
	}
	webClientCookieDuration = time.Duration(minutes) * time.Minute
	return nil
}
