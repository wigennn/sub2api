//go:build unit

package service_test

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/ent/authidentity"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestLoginOrRegisterMainSiteUserCreatesUserAndIdentity(t *testing.T) {
	svc, _, client := newAuthServiceWithEnt(t, map[string]string{
		service.SettingKeyRegistrationEnabled: "false",
	}, nil)
	ctx := context.Background()

	user, err := svc.LoginOrRegisterMainSiteUser(ctx, service.MainSiteUserInput{
		UserID:      1001,
		Email:       "main-site@example.com",
		Username:    "main-user",
		DisplayName: "Main User",
		Roles:       []string{"USER"},
		Permissions: []string{"menu:home"},
	})
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, "main-site@example.com", user.Email)
	require.Equal(t, "main-user", user.Username)
	require.Equal(t, service.RoleUser, user.Role)
	require.Equal(t, "oidc", user.SignupSource)

	identity, err := client.AuthIdentity.Query().
		Where(
			authidentity.ProviderTypeEQ(service.MainSiteProviderType),
			authidentity.ProviderKeyEQ(service.MainSiteProviderKey),
			authidentity.ProviderSubjectEQ("1001"),
		).
		Only(ctx)
	require.NoError(t, err)
	require.Equal(t, user.ID, identity.UserID)
	require.Equal(t, float64(1001), identity.Metadata["main_site_user_id"])
}

func TestLoginOrRegisterMainSiteUserReusesBoundIdentity(t *testing.T) {
	svc, _, _ := newAuthServiceWithEnt(t, map[string]string{
		service.SettingKeyRegistrationEnabled: "false",
	}, nil)
	ctx := context.Background()
	input := service.MainSiteUserInput{
		UserID:   2002,
		Email:    "same-user@example.com",
		Username: "same-user",
	}

	first, err := svc.LoginOrRegisterMainSiteUser(ctx, input)
	require.NoError(t, err)
	second, err := svc.LoginOrRegisterMainSiteUser(ctx, input)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
}
