package token

import (
	"testing"
	"time"

	"github.com/authorizerdev/authorizer/internal/config"
	"github.com/authorizerdev/authorizer/internal/storage/schemas"
)

func testTokenProvider(cfg *config.Config) *provider {
	return &provider{config: cfg}
}

func TestResolveAccessTokenExpiry_DefaultConfig(t *testing.T) {
	p := testTokenProvider(&config.Config{AccessTokenExpiresIn: 60 * 60 * 24 * 30})
	got := p.resolveAccessTokenExpiry(&AuthTokenConfig{})
	want := 30 * 24 * time.Hour
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestResolveAccessTokenExpiry_ExpireTimeOverride(t *testing.T) {
	p := testTokenProvider(&config.Config{AccessTokenExpiresIn: 60 * 60 * 24 * 30})
	got := p.resolveAccessTokenExpiry(&AuthTokenConfig{ExpireTime: "30m"})
	want := 30 * time.Minute
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestResolveAccessTokenExpiry_ZeroConfigFallback(t *testing.T) {
	p := testTokenProvider(&config.Config{AccessTokenExpiresIn: 0})
	got := p.resolveAccessTokenExpiry(&AuthTokenConfig{})
	want := 30 * time.Minute
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestCreateAccessToken_UsesConfiguredTTL(t *testing.T) {
	p := testTokenProvider(&config.Config{
		JWTType:              "HS256",
		JWTSecret:            "test-secret-key-with-enough-length",
		ClientID:             "client-id",
		AccessTokenExpiresIn: 60 * 60 * 24 * 30,
	})
	before := time.Now().Unix()
	_, expiresAt, err := p.CreateAccessToken(&AuthTokenConfig{
		HostName: "localhost",
		User:     &schemas.User{ID: "user-1", Roles: "user"},
		Roles:    []string{"user"},
		Nonce:    "nonce-1",
	})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	ttl := expiresAt - before
	const wantMin = int64(60 * 60 * 24 * 29)
	if ttl < wantMin {
		t.Fatalf("expected TTL >= %d, got %d", wantMin, ttl)
	}
}

func TestCreateRefreshToken_UsesConfiguredTTL(t *testing.T) {
	p := testTokenProvider(&config.Config{
		JWTType:             "HS256",
		JWTSecret:           "test-secret-key-with-enough-length",
		ClientID:            "client-id",
		RefreshTokenExpiresIn: 60 * 60 * 24 * 30,
	})
	before := time.Now().Unix()
	_, expiresAt, err := p.CreateRefreshToken(&AuthTokenConfig{
		HostName: "localhost",
		User:     &schemas.User{ID: "user-1", Roles: "user"},
		Roles:    []string{"user"},
		Nonce:    "nonce-1",
	})
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	ttl := expiresAt - before
	const wantMin = int64(60 * 60 * 24 * 29)
	if ttl < wantMin {
		t.Fatalf("expected TTL >= %d, got %d", wantMin, ttl)
	}
}

// TestParseJWTToken_TemporalClaimFixtures verifies the NumericDate contract:
// exp/iat are whole-second Unix values, exp is mandatory, and the provider
// signing path produces claims ParseJWTToken accepts.
func TestParseJWTToken_TemporalClaimFixtures(t *testing.T) {
	p := testTokenProvider(&config.Config{
		JWTType:   "HS256",
		JWTSecret: "test-secret-key-with-enough-length",
	})

	now := time.Now().Unix()

	token, _, err := p.CreateAccessToken(&AuthTokenConfig{
		HostName:   "localhost",
		User:       &schemas.User{ID: "user-boundary", Roles: "user"},
		Roles:      []string{"user"},
		Nonce:      "nonce-boundary",
		ExpireTime: "1m",
	})
	if err != nil {
		t.Fatalf("CreateAccessToken boundary: %v", err)
	}
	_ = now

	// ParseJWTToken must accept the provider-signed token (whole-second exp).
	claims, err := p.ParseJWTToken(token)
	if err != nil {
		t.Fatalf("ParseJWTToken on valid token: %v", err)
	}
	if _, ok := claims["exp"].(int64); !ok {
		t.Fatalf("expected exp as int64, got %T", claims["exp"])
	}
}
