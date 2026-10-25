//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestBuildMainSiteUserInfoURL(t *testing.T) {
	endpoint, err := buildMainSiteUserInfoURL("https://main.example.com/", "/api/auth/me")
	require.NoError(t, err)
	require.Equal(t, "https://main.example.com/api/auth/me", endpoint)
}

func TestBuildMainSiteSSOURL(t *testing.T) {
	endpoint, err := buildMainSiteSSOURL(
		"https://main.example.com/",
		"https://sub.example.com/login?redirect=%2Fdashboard",
	)
	require.NoError(t, err)
	require.Equal(
		t,
		"https://main.example.com/api/auth/sso/handoff?redirect_uri=https%3A%2F%2Fsub.example.com%2Flogin%3Fredirect%3D%252Fdashboard",
		endpoint,
	)
}

func TestBuildMainSiteCallbackURLUsesForwardedHTTPS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "http://sub.example.com/api/v1/auth/main-site/start", nil)
	c.Request.Host = "sub.example.com"
	c.Request.Header.Set("X-Forwarded-Proto", "https")

	callbackURL, err := buildMainSiteCallbackURL(c, "")
	require.NoError(t, err)
	require.Equal(t, "https://sub.example.com/login", callbackURL)
}

func TestBuildMainSiteCallbackURLPrefersConfiguredFrontendURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "http://internal:8070/api/v1/auth/main-site/start", nil)

	callbackURL, err := buildMainSiteCallbackURL(c, "https://subapi.aitutu.online")
	require.NoError(t, err)
	require.Equal(t, "https://subapi.aitutu.online/login", callbackURL)
}

func TestMainSiteOnlyAuthPathAllowlist(t *testing.T) {
	for _, allowed := range []string{
		"/api/v1/auth/main-site/start",
		"/api/v1/auth/main-site/exchange",
		"/api/v1/auth/login/2fa",
		"/api/v1/auth/refresh",
		"/api/v1/auth/logout",
		"/api/v1/auth/oauth/wechat/payment/start",
		"/api/v1/auth/oauth/wechat/payment/callback",
	} {
		require.True(t, mainSiteOnlyAllowsAuthPath(allowed), allowed)
	}
	for _, blocked := range []string{
		"/api/v1/auth/register",
		"/api/v1/auth/login",
		"/api/v1/auth/passkey/login/begin",
		"/api/v1/auth/oauth/github/start",
		"/api/v1/auth/forgot-password",
	} {
		require.False(t, mainSiteOnlyAllowsAuthPath(blocked), blocked)
	}
}

func TestResolveMainSiteTokenPrefersBodyAndAcceptsCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/main-site/exchange", nil)
	c.Request.AddCookie(&http.Cookie{Name: "token", Value: "cookie-token"})
	require.Equal(t, "cookie-token", resolveMainSiteToken(c, ""))
	require.Equal(t, "body-token", resolveMainSiteToken(c, "body-token"))
}

func TestFetchMainSiteUserParsesAiBasicEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/auth/me", r.URL.Path)
		require.Equal(t, "Bearer main-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"data": {
				"id": 88,
				"username": "novel-user",
				"email": "novel@example.com",
				"nickname": "Novel User",
				"status": "ACTIVE",
				"roles": ["USER"],
				"permissions": ["menu:home"]
			}
		}`))
	}))
	defer server.Close()

	h := &AuthHandler{cfg: &config.Config{MainSite: config.MainSiteAuthConfig{
		Enabled:        true,
		BaseURL:        server.URL,
		UserInfoPath:   "/api/auth/me",
		TimeoutSeconds: 2,
	}}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/main-site/exchange", nil)

	info, err := h.fetchMainSiteUser(c, "main-token")
	require.NoError(t, err)
	require.Equal(t, int64(88), info.ID)
	require.Equal(t, "novel@example.com", info.Email)
	require.Equal(t, "Novel User", info.Nickname)
}
