// Copyright (C) 2026 Harbor Drive contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpd

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/require"
)

func TestHarborWebClientCookiePolicy(t *testing.T) {
	previous := webClientCookieDuration
	t.Cleanup(func() { webClientCookieDuration = previous })
	admin := getTokenDuration(tokenAudienceWebAdmin)
	api := getTokenDuration(tokenAudienceAPI)
	share := getTokenDuration(tokenAudienceWebShare)
	csrf := getTokenDuration(tokenAudienceCSRF)
	partial := getTokenDuration(tokenAudienceWebClientPartial)
	require.NoError(t, configureWebClientCookieDuration(31*24*60))
	require.Equal(t, 31*24*time.Hour, getTokenDuration(tokenAudienceWebClient))
	require.Equal(t, 31*24*time.Hour, getMaxCookieDuration())
	require.Equal(t, admin, getTokenDuration(tokenAudienceWebAdmin))
	require.Equal(t, api, getTokenDuration(tokenAudienceAPI))
	require.Equal(t, api, getTokenDuration(tokenAudienceAPIUser))
	require.Equal(t, share, getTokenDuration(tokenAudienceWebShare))
	require.Equal(t, csrf, getTokenDuration(tokenAudienceCSRF))
	require.Equal(t, partial, getTokenDuration(tokenAudienceWebClientPartial))
	require.Error(t, configureWebClientCookieDuration(-1))
	require.Error(t, configureWebClientCookieDuration(31*24*60+1))
	require.NoError(t, configureWebClientCookieDuration(0))
	require.Equal(t, cookieTokenDuration, getTokenDuration(tokenAudienceWebClient))
}

func TestHarborLongCookieAccountRevocation(t *testing.T) {
	previousDuration, previousValidation := webClientCookieDuration, tokenValidationMode
	t.Cleanup(func() { webClientCookieDuration, tokenValidationMode = previousDuration, previousValidation })
	require.NoError(t, configureWebClientCookieDuration(31*24*60))
	tokenValidationMode = 0
	user := dataprovider.User{BaseUser: sdk.BaseUser{
		Username: "harbor-cookie-" + xid.New().String(), Password: "initial-test-password",
		HomeDir: t.TempDir(), Status: 1,
	}}
	user.Permissions = map[string][]string{"/": {dataprovider.PermListItems, dataprovider.PermDownload}}
	require.NoError(t, dataprovider.AddUser(&user, "", "", ""))
	t.Cleanup(func() { _ = dataprovider.DeleteUser(user.Username, "", "", "") })
	user, err := dataprovider.GetUserWithGroupSettings(user.Username, "")
	require.NoError(t, err)
	claims := jwt.NewClaims(tokenAudienceWebClient, "127.0.0.1", getTokenDuration(tokenAudienceWebClient))
	claims.Username, claims.Subject = user.Username, user.GetSignature()
	req := httptest.NewRequest("GET", "/web/client/files", nil)
	require.NoError(t, checkTokenSignature(req, claims))
	user.Password = "changed-test-password"
	require.NoError(t, dataprovider.UpdateUser(&user, "", "", ""))
	require.Error(t, checkTokenSignature(req, claims))
	// The override must not silently change API or administrator validation mode.
	for _, audience := range []string{tokenAudienceWebAdmin, tokenAudienceAPI, tokenAudienceAPIUser, tokenAudienceWebClientPartial} {
		other := jwt.NewClaims(audience, "127.0.0.1", time.Minute)
		other.Username, other.Subject = "missing-user", "stale-signature"
		require.NoError(t, checkTokenSignature(req, other))
	}
}

func TestHarborLongCookieRevocationUsesOnlyPersistentHash(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("requires a SQL provider")
	}
	value := "harbor-test-bearer-" + xid.New().String()
	manager := &dbTokenManager{hashOnly: true}
	key := manager.getKey(value)
	t.Cleanup(func() { _ = dataprovider.DeleteSharedSession(key, dataprovider.SessionTypeInvalidToken) })
	manager.Add(value, time.Now().Add(31*24*time.Hour))
	stored, err := dataprovider.GetSharedSession(key, dataprovider.SessionTypeInvalidToken)
	require.NoError(t, err)
	require.NotContains(t, fmt.Sprint(stored.Data), value)
	if data, ok := stored.Data.([]byte); ok {
		require.NotContains(t, string(data), value)
		require.True(t, strings.Contains(string(data), "revoked"))
	}
	// A newly created manager has no in-memory state, just like after restart.
	require.True(t, (&dbTokenManager{hashOnly: true}).Get(value))
}
