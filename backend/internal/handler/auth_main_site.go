package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

const mainSiteUserInfoMaxBytes = 64 * 1024

type mainSiteExchangeRequest struct {
	AccessToken string `json:"access_token"`
}

type mainSiteUserInfo struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Phone       string   `json:"phone"`
	Nickname    string   `json:"nickname"`
	Avatar      string   `json:"avatar"`
	Status      string   `json:"status"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type mainSiteUserInfoEnvelope struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// MainSiteLoginStart sends the browser through the main-site login and
// returns to this deployment with an identity handoff in the URL fragment.
// GET /api/v1/auth/main-site/start
func (h *AuthHandler) MainSiteLoginStart(c *gin.Context) {
	if h == nil || !service.MainSiteAuthEnabled(h.cfg) {
		response.ErrorFrom(c, infraerrors.NotFound("MAIN_SITE_AUTH_DISABLED", "main site login is not enabled"))
		return
	}

	frontendURL := ""
	if h.settingSvc != nil {
		frontendURL = h.settingSvc.GetFrontendURL(c.Request.Context())
	}
	callbackURL, err := buildMainSiteCallbackURL(c, frontendURL)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	startURL, err := buildMainSiteSSOURL(h.cfg.MainSite.BaseURL, callbackURL)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(http.StatusFound, startURL)
}

// MainSiteOnlyAuthGuard rejects local account flows when the main site is the
// only allowed identity provider. Session maintenance and payment OAuth remain
// available so existing logins can refresh, log out, and complete payments.
func (h *AuthHandler) MainSiteOnlyAuthGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || !service.MainSiteOnlyLoginEnabled(h.cfg) || mainSiteOnlyAllowsAuthPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		response.ErrorFrom(c, infraerrors.Forbidden(
			"MAIN_SITE_LOGIN_REQUIRED",
			"local authentication is disabled; sign in through the main site",
		))
		c.Abort()
	}
}

func mainSiteOnlyAllowsAuthPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, suffix := range []string{
		"/auth/main-site/start",
		"/auth/main-site/exchange",
		"/auth/login/2fa",
		"/auth/refresh",
		"/auth/logout",
		"/auth/oauth/wechat/payment/start",
		"/auth/oauth/wechat/payment/callback",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// MainSiteExchange exchanges a trusted ai-basic token for a sub2api session.
// POST /api/v1/auth/main-site/exchange
func (h *AuthHandler) MainSiteExchange(c *gin.Context) {
	if h == nil || h.authService == nil || !service.MainSiteAuthEnabled(h.cfg) {
		response.ErrorFrom(c, infraerrors.NotFound("MAIN_SITE_AUTH_DISABLED", "main site login is not enabled"))
		return
	}

	var req mainSiteExchangeRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			response.BadRequest(c, "Invalid request: "+err.Error())
			return
		}
	}

	token := resolveMainSiteToken(c, req.AccessToken)
	if token == "" {
		response.ErrorFrom(c, infraerrors.Unauthorized("MAIN_SITE_TOKEN_MISSING", "main site token is missing"))
		return
	}

	info, err := h.fetchMainSiteUser(c, token)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	user, err := h.authService.LoginOrRegisterMainSiteUser(c.Request.Context(), service.MainSiteUserInput{
		UserID:      info.ID,
		Email:       info.Email,
		Username:    firstMainSiteValue(info.Username, info.Nickname),
		DisplayName: info.Nickname,
		AvatarURL:   info.Avatar,
		Roles:       info.Roles,
		Permissions: info.Permissions,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	if err := h.ensureBackendModeAllowsUser(c.Request.Context(), user); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	if h.totpService != nil && h.settingSvc != nil &&
		h.settingSvc.IsTotpEnabled(c.Request.Context()) && user.TotpEnabled {
		tempToken, err := h.totpService.CreateLoginSession(c.Request.Context(), user.ID, user.Email)
		if err != nil {
			response.InternalError(c, "Failed to create 2FA session")
			return
		}
		response.Success(c, TotpLoginResponse{
			Requires2FA:     true,
			TempToken:       tempToken,
			UserEmailMasked: service.MaskEmail(user.Email),
		})
		return
	}

	h.authService.RecordSuccessfulLogin(c.Request.Context(), user.ID)
	h.respondWithTokenPair(c, user)
}

func resolveMainSiteToken(c *gin.Context, bodyToken string) string {
	if token := strings.TrimSpace(bodyToken); token != "" {
		return token
	}
	if token := strings.TrimSpace(c.GetHeader("X-Main-Site-Token")); token != "" {
		return token
	}
	if cookie, err := c.Cookie("token"); err == nil {
		if token := strings.TrimSpace(cookie); token != "" {
			return token
		}
	}
	return ""
}

func (h *AuthHandler) fetchMainSiteUser(c *gin.Context, token string) (*mainSiteUserInfo, error) {
	endpoint, err := buildMainSiteUserInfoURL(h.cfg.MainSite.BaseURL, h.cfg.MainSite.UserInfoPath)
	if err != nil {
		return nil, infraerrors.InternalServer("MAIN_SITE_AUTH_CONFIG_INVALID", "main site auth URL is invalid").WithCause(err)
	}

	timeout := time.Duration(h.cfg.MainSite.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, infraerrors.InternalServer("MAIN_SITE_AUTH_REQUEST_FAILED", "failed to create main site auth request").WithCause(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("MAIN_SITE_UNAVAILABLE", "main site authentication is unavailable").WithCause(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, mainSiteUserInfoMaxBytes))
	if err != nil {
		return nil, infraerrors.ServiceUnavailable("MAIN_SITE_RESPONSE_INVALID", "failed to read main site authentication response").WithCause(err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, infraerrors.Unauthorized("MAIN_SITE_TOKEN_INVALID", "main site token is invalid or expired")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.ServiceUnavailable("MAIN_SITE_AUTH_FAILED", "main site authentication failed")
	}

	var envelope mainSiteUserInfoEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Data) > 0 {
		if !envelope.Success {
			message := strings.TrimSpace(envelope.Message)
			if message == "" {
				message = "main site token is invalid"
			}
			return nil, infraerrors.Unauthorized("MAIN_SITE_TOKEN_INVALID", message)
		}
		body = envelope.Data
	}

	var info mainSiteUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, infraerrors.ServiceUnavailable("MAIN_SITE_RESPONSE_INVALID", "main site returned an invalid user profile").WithCause(err)
	}
	if info.ID <= 0 || strings.TrimSpace(info.Email) == "" {
		return nil, infraerrors.ServiceUnavailable("MAIN_SITE_PROFILE_INCOMPLETE", "main site user profile is incomplete")
	}
	if info.Status != "" && !strings.EqualFold(strings.TrimSpace(info.Status), "ACTIVE") {
		return nil, infraerrors.Forbidden("MAIN_SITE_USER_DISABLED", "main site user is disabled")
	}
	return &info, nil
}

func buildMainSiteUserInfoURL(baseURL, userInfoPath string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", infraerrors.BadRequest("MAIN_SITE_BASE_URL_INVALID", "main site base URL is invalid")
	}
	path := strings.TrimSpace(userInfoPath)
	if path == "" {
		path = "/api/auth/me"
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func buildMainSiteSSOURL(baseURL, callbackURL string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", infraerrors.BadRequest("MAIN_SITE_BASE_URL_INVALID", "main site base URL is invalid")
	}
	endpoint := base.ResolveReference(&url.URL{Path: "/api/auth/sso/handoff"})
	query := endpoint.Query()
	query.Set("redirect_uri", callbackURL)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func buildMainSiteCallbackURL(c *gin.Context, frontendURL string) (string, error) {
	if base, err := url.Parse(strings.TrimSpace(frontendURL)); err == nil && base.Scheme != "" && base.Host != "" {
		return base.ResolveReference(&url.URL{Path: "/login"}).String(), nil
	}
	host := strings.TrimSpace(c.Request.Host)
	if host == "" {
		return "", infraerrors.BadRequest("MAIN_SITE_CALLBACK_INVALID", "request host is missing")
	}
	scheme := "http"
	if isRequestHTTPS(c) {
		scheme = "https"
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: "/login"}).String(), nil
}

func firstMainSiteValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
