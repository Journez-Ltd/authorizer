package graphql

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"

	"github.com/authorizerdev/authorizer/internal/constants"
	"github.com/authorizerdev/authorizer/internal/cookie"
	"github.com/authorizerdev/authorizer/internal/graph/model"
	"github.com/authorizerdev/authorizer/internal/parsers"
	"github.com/authorizerdev/authorizer/internal/refs"
	"github.com/authorizerdev/authorizer/internal/storage/schemas"
	"github.com/authorizerdev/authorizer/internal/token"
	"github.com/authorizerdev/authorizer/internal/utils"
)

// SocialLogin handles login/signup via client-side social provider id_token.
// Supports Flutter google_sign_in and sign_in_with_apple packages.
func (g *graphqlProvider) SocialLogin(ctx context.Context, params *model.SocialLoginRequest) (*model.AuthResponse, error) {
	log := g.Log.With().Str("func", "SocialLogin").Logger()

	gc, err := utils.GinContextFromContext(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get gin context")
		return nil, err
	}

	provider := strings.TrimSpace(params.Provider)
	rawIDToken := strings.TrimSpace(params.IDToken)
	if provider == "" || rawIDToken == "" {
		return nil, fmt.Errorf("provider and id_token are required")
	}

	// Phase 1: Verify ID token based on provider
	var user *schemas.User
	switch provider {
	case constants.AuthRecipeMethodGoogle:
		if g.Config.GoogleClientID == "" {
			return nil, fmt.Errorf("google login is not enabled")
		}
		user, err = g.verifyGoogleIDToken(ctx, rawIDToken)
	case constants.AuthRecipeMethodApple:
		if g.Config.AppleClientID == "" {
			return nil, fmt.Errorf("apple login is not enabled")
		}
		user, err = g.verifyAppleIDToken(ctx, rawIDToken, params.GivenName, params.FamilyName)
	default:
		return nil, fmt.Errorf("unsupported social login provider: %s", provider)
	}
	if err != nil {
		log.Debug().Err(err).Str("provider", provider).Msg("Failed to verify id_token")
		return nil, fmt.Errorf("failed to verify id_token: %s", err.Error())
	}
	if user == nil || refs.StringValue(user.Email) == "" {
		return nil, fmt.Errorf("unable to extract email from id_token")
	}

	email := refs.StringValue(user.Email)
	log = log.With().Str("email", email).Str("provider", provider).Logger()

	// Determine roles
	inputRoles := g.Config.DefaultRoles
	if params.Roles != nil && len(params.Roles) > 0 {
		inputRoles = params.Roles
	}

	// Determine scopes
	scopes := []string{"openid", "email", "profile"}
	if params.Scope != nil && len(params.Scope) > 0 {
		scopes = params.Scope
	}

	// Phase 2: Lookup / create / update user
	existingUser, err := g.StorageProvider.GetUserByEmail(ctx, email)
	isSignUp := false

	if err != nil {
		// User not found — create new user
		if !g.Config.EnableSignup {
			log.Debug().Msg("Signup is disabled")
			return nil, fmt.Errorf("signup is disabled for this instance")
		}

		user.SignupMethods = provider

		// Validate roles don't include protected roles
		hasProtectedRole := false
		for _, ir := range inputRoles {
			if utils.StringSliceContains(g.Config.ProtectedRoles, ir) {
				hasProtectedRole = true
			}
		}
		if hasProtectedRole {
			log.Debug().Msg("Invalid role: user is using protected role")
			return nil, fmt.Errorf("invalid role")
		}

		user.Roles = strings.Join(inputRoles, ",")
		now := time.Now().Unix()
		user.EmailVerifiedAt = &now

		user, err = g.StorageProvider.AddUser(ctx, user)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to add user")
			return nil, err
		}
		isSignUp = true
	} else {
		// User exists
		if existingUser.RevokedTimestamp != nil {
			log.Debug().Msg("User access has been revoked")
			return nil, fmt.Errorf("user access has been revoked")
		}

		// Anti-pre-hijacking: if existing account email was never verified,
		// delete it and treat OAuth user as new signup
		if existingUser.EmailVerifiedAt == nil {
			log.Info().Msg("Removing unverified pre-existing account before social login signup")
			if err := g.StorageProvider.DeleteUser(ctx, existingUser); err != nil {
				log.Debug().Err(err).Msg("Failed to delete unverified user")
				return nil, fmt.Errorf("failed to process social login")
			}

			hasProtectedRole := false
			for _, ir := range inputRoles {
				if utils.StringSliceContains(g.Config.ProtectedRoles, ir) {
					hasProtectedRole = true
				}
			}
			if hasProtectedRole {
				log.Debug().Msg("Invalid role: user is using protected role")
				return nil, fmt.Errorf("invalid role")
			}

			user.SignupMethods = provider
			user.Roles = strings.Join(inputRoles, ",")
			now := time.Now().Unix()
			user.EmailVerifiedAt = &now

			user, err = g.StorageProvider.AddUser(ctx, user)
			if err != nil {
				log.Debug().Err(err).Msg("Failed to add user after removing unverified account")
				return nil, err
			}
			isSignUp = true
		} else {
			// Existing verified user — update
			user = existingUser

			signupMethod := existingUser.SignupMethods
			if !strings.Contains(signupMethod, provider) {
				signupMethod = signupMethod + "," + provider
			}
			user.SignupMethods = signupMethod

			// Merge unassigned roles
			existingRoles := strings.Split(existingUser.Roles, ",")
			unassignedRoles := []string{}
			for _, ir := range inputRoles {
				if !utils.StringSliceContains(existingRoles, ir) {
					unassignedRoles = append(unassignedRoles, ir)
				}
			}

			if len(unassignedRoles) > 0 {
				hasProtectedRole := false
				for _, ur := range unassignedRoles {
					if utils.StringSliceContains(g.Config.ProtectedRoles, ur) {
						hasProtectedRole = true
					}
				}
				if hasProtectedRole {
					log.Debug().Msg("Invalid role: user is using protected role")
					return nil, fmt.Errorf("invalid role")
				}
				user.Roles = existingUser.Roles + "," + strings.Join(unassignedRoles, ",")
			} else {
				user.Roles = existingUser.Roles
			}

			user, err = g.StorageProvider.UpdateUser(ctx, user)
			if err != nil {
				log.Debug().Err(err).Msg("Failed to update user")
				return nil, err
			}
		}
	}

	// Phase 3: Create tokens & session
	roles := strings.Split(user.Roles, ",")
	nonce := uuid.New().String()
	hostname := parsers.GetHost(gc)

	authToken, err := g.TokenProvider.CreateAuthToken(gc, &token.AuthTokenConfig{
		User:        user,
		Roles:       roles,
		Scope:       scopes,
		LoginMethod: provider,
		Nonce:       nonce,
		HostName:    hostname,
	})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create auth token")
		return nil, err
	}

	expiresIn := authToken.AccessToken.ExpiresAt - time.Now().Unix()
	if expiresIn <= 0 {
		expiresIn = 1
	}

	res := &model.AuthResponse{
		Message:     "Logged in successfully",
		AccessToken: &authToken.AccessToken.Token,
		IDToken:     &authToken.IDToken.Token,
		ExpiresIn:   &expiresIn,
		User:        user.AsAPIUser(),
	}

	cookie.SetSession(gc, authToken.FingerPrintHash, g.Config.AppCookieSecure)
	sessionStoreKey := provider + ":" + user.ID
	g.MemoryStoreProvider.SetUserSession(sessionStoreKey, constants.TokenTypeSessionToken+"_"+authToken.FingerPrint, authToken.FingerPrintHash, authToken.SessionTokenExpiresAt)
	g.MemoryStoreProvider.SetUserSession(sessionStoreKey, constants.TokenTypeAccessToken+"_"+authToken.FingerPrint, authToken.AccessToken.Token, authToken.AccessToken.ExpiresAt)

	if authToken.RefreshToken != nil {
		res.RefreshToken = &authToken.RefreshToken.Token
		g.MemoryStoreProvider.SetUserSession(sessionStoreKey, constants.TokenTypeRefreshToken+"_"+authToken.FingerPrint, authToken.RefreshToken.Token, authToken.RefreshToken.ExpiresAt)
	}

	// Phase 4: Fire events asynchronously
	go func() {
		if isSignUp {
			g.EventsProvider.RegisterEvent(ctx, constants.UserSignUpWebhookEvent, provider, user)
		}
		g.EventsProvider.RegisterEvent(ctx, constants.UserLoginWebhookEvent, provider, user)
		if err := g.StorageProvider.AddSession(ctx, &schemas.Session{
			UserID:    user.ID,
			UserAgent: utils.GetUserAgent(gc.Request),
			IP:        utils.GetIP(gc.Request),
		}); err != nil {
			log.Debug().Err(err).Msg("Failed to add session")
		}
	}()

	return res, nil
}

// verifyGoogleIDToken verifies a Google ID token using OIDC and extracts user claims.
func (g *graphqlProvider) verifyGoogleIDToken(ctx context.Context, rawIDToken string) (*schemas.User, error) {
	oidcProvider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc provider: %s", err.Error())
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: g.Config.GoogleClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify id_token: %s", err.Error())
	}

	user := &schemas.User{}
	if err := idToken.Claims(user); err != nil {
		return nil, fmt.Errorf("unable to extract claims: %s", err.Error())
	}

	return user, nil
}

// verifyAppleIDToken verifies an Apple identity token using OIDC and extracts user claims.
// Apple only provides given_name/family_name on first authorization, so they must be passed separately.
func (g *graphqlProvider) verifyAppleIDToken(ctx context.Context, rawIDToken string, givenName *string, familyName *string) (*schemas.User, error) {
	oidcProvider, err := oidc.NewProvider(ctx, "https://appleid.apple.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc provider: %s", err.Error())
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: g.Config.AppleClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify identity_token: %s", err.Error())
	}

	user := &schemas.User{}
	if err := idToken.Claims(user); err != nil {
		return nil, fmt.Errorf("unable to extract claims: %s", err.Error())
	}

	// Apple only sends name on first authorization — override from params if provided
	if givenName != nil && *givenName != "" {
		user.GivenName = givenName
	}
	if familyName != nil && *familyName != "" {
		user.FamilyName = familyName
	}

	return user, nil
}
