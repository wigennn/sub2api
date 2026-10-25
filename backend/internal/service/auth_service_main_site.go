package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

const (
	MainSiteProviderType = "oidc"
	MainSiteProviderKey  = "main-site"
)

type MainSiteUserInput struct {
	UserID      int64
	Email       string
	Username    string
	DisplayName string
	AvatarURL   string
	Roles       []string
	Permissions []string
}

// LoginOrRegisterMainSiteUser maps a verified ai-basic identity into the local
// auth_identities table and returns the corresponding sub2api user.
// Main-site users are auto-provisioned even when local email registration is disabled.
func (s *AuthService) LoginOrRegisterMainSiteUser(ctx context.Context, input MainSiteUserInput) (*User, error) {
	if s == nil || s.userRepo == nil || s.entClient == nil {
		return nil, ErrServiceUnavailable
	}
	if input.UserID <= 0 {
		return nil, infraerrors.BadRequest("MAIN_SITE_USER_ID_MISSING", "main site user id is missing")
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" || len(email) > 255 {
		return nil, infraerrors.BadRequest("MAIN_SITE_EMAIL_MISSING", "main site user email is missing")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, infraerrors.BadRequest("MAIN_SITE_EMAIL_INVALID", "main site user email is invalid")
	}

	subject := strconv.FormatInt(input.UserID, 10)
	user, err := s.findEmailOAuthIdentityOwner(ctx, MainSiteProviderType, MainSiteProviderKey, subject)
	if err != nil {
		return nil, err
	}

	if user == nil {
		user, err = s.userRepo.GetByEmail(ctx, email)
		if err != nil {
			if !errors.Is(err, ErrUserNotFound) {
				logger.LegacyPrintf("service.auth", "[Auth] Database error during main-site login: %v", err)
				return nil, ErrServiceUnavailable
			}
			user, err = s.createMainSiteUser(ctx, email, input.Username)
			if err != nil {
				return nil, err
			}
		}
	}

	if user == nil {
		return nil, ErrServiceUnavailable
	}
	if !user.IsActive() {
		return nil, ErrUserNotActive
	}

	metadata := map[string]any{
		"main_site_user_id":     input.UserID,
		"main_site_roles":       input.Roles,
		"main_site_permissions": input.Permissions,
	}
	if strings.TrimSpace(input.DisplayName) != "" {
		metadata["display_name"] = strings.TrimSpace(input.DisplayName)
	}
	if err := s.ensureEmailOAuthIdentity(ctx, user.ID, EmailOAuthIdentityInput{
		ProviderType:     MainSiteProviderType,
		ProviderKey:      MainSiteProviderKey,
		ProviderSubject:  subject,
		Email:            email,
		EmailVerified:    true,
		Username:         strings.TrimSpace(input.Username),
		DisplayName:      strings.TrimSpace(input.DisplayName),
		AvatarURL:        strings.TrimSpace(input.AvatarURL),
		UpstreamMetadata: metadata,
	}); err != nil {
		return nil, err
	}

	fields := UserUpdateFields{}
	username := strings.TrimSpace(input.Username)
	if username != "" && (user.Username == "" || strings.TrimSpace(user.Username) != username) {
		user.Username = username
		fields.Username = true
	}
	if !strings.EqualFold(strings.TrimSpace(user.Email), email) {
		if _, lookupErr := s.userRepo.GetByEmail(ctx, email); errors.Is(lookupErr, ErrUserNotFound) {
			user.Email = email
			fields.Email = true
		}
	}
	if !fields.IsEmpty() {
		if err := s.userRepo.Update(ctx, user, fields); err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] Failed to sync main-site profile for user %d: %v", user.ID, err)
		}
	}

	return user, nil
}

func (s *AuthService) createMainSiteUser(ctx context.Context, email, username string) (*User, error) {
	randomPassword, err := randomHexString(32)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	hashedPassword, err := s.HashPassword(randomPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	signupSource := MainSiteProviderType
	grantPlan := s.resolveSignupGrantPlan(ctx, signupSource)
	var defaultRPMLimit int
	if s.settingService != nil {
		defaultRPMLimit = s.settingService.GetDefaultUserRPMLimit(ctx)
	}
	user := &User{
		Email:        email,
		Username:     strings.TrimSpace(username),
		PasswordHash: hashedPassword,
		Role:         RoleUser,
		Balance:      grantPlan.Balance,
		Concurrency:  grantPlan.Concurrency,
		RPMLimit:     defaultRPMLimit,
		Status:       StatusActive,
		SignupSource: signupSource,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		if errors.Is(err, ErrEmailExists) {
			existing, loadErr := s.userRepo.GetByEmail(ctx, email)
			if loadErr != nil {
				return nil, ErrServiceUnavailable
			}
			return existing, nil
		}
		logger.LegacyPrintf("service.auth", "[Auth] Failed to create main-site user: %v", err)
		return nil, ErrServiceUnavailable
	}

	s.postAuthUserBootstrap(ctx, user, signupSource, false)
	s.assignSubscriptions(ctx, user.ID, grantPlan.Subscriptions, "auto assigned by main-site signup")
	_ = s.snapshotPlatformQuotaDefaults(ctx, user.ID, &grantPlan)
	return user, nil
}

func MainSiteAuthEnabled(cfg *config.Config) bool {
	return cfg != nil &&
		cfg.MainSite.Enabled &&
		strings.TrimSpace(cfg.MainSite.BaseURL) != ""
}

// MainSiteOnlyLoginEnabled reports whether local authentication flows must be
// rejected in favor of the main-site identity provider.
func MainSiteOnlyLoginEnabled(cfg *config.Config) bool {
	return MainSiteAuthEnabled(cfg) && cfg.MainSite.OnlyLogin
}
