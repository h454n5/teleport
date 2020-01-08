package auth

//CreateUserWithoutOTP creates an account with the provided password and deletes the token afterwards.
import (
	"fmt"
	"net/url"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

// CreateInviteToken invites a user
func (s *AuthServer) CreateInviteToken(req services.CreateUserInviteRequest) (services.UserToken, error) {
	err := req.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	userInvite := services.UserInvite{
		Name:  req.Name,
		Roles: req.Roles,
	}

	if err := userInvite.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Validate that requested roles exist.
	for _, role := range req.Roles {
		if _, err := s.GetRole(role); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// Verify that user does not exist
	_, err = s.GetUser(req.Name, false)
	if err == nil {
		return nil, trace.BadParameter("user(%v) already registered", req.Name)
	}

	_, err = s.UpsertUserInvite(userInvite)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	inviteToken, err := s.createUserToken(services.UserTokenTypeInvite, userInvite.Name, req.TTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	url, err := formatUserTokenURL(s.publicURL(), fmt.Sprintf("/web/newuser/%v", inviteToken.GetName()))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	inviteToken.SetURL(url)

	err = s.DeleteUserTokens(services.UserTokenTypeInvite, userInvite.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.CreateUserToken(inviteToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s.GetUserToken(inviteToken.GetName())
}

func (s *AuthServer) createUserToken(tokenType string, name string, ttl time.Duration) (services.UserToken, error) {
	token, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// This OTP secret and QR code are never actually used. The OTP secret and
	// QR code are rotated every time the signup link is show to the user, see
	// the "GetSignupTokenData" function for details on why this is done. We
	// generate a OTP token because it causes no harm and makes tests easier to
	// write.
	accountName := name + "@" + s.AuthServiceName
	_, otpQRCode, err := s.initializeTOTP(accountName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	userToken := services.NewUserToken(token)
	userToken.Metadata.SetExpiry(s.clock.Now().UTC().Add(ttl))
	userToken.Spec.Type = tokenType
	userToken.Spec.User = name
	userToken.Spec.QRCode = string(otpQRCode)
	userToken.Spec.Created = s.clock.Now().UTC()
	return &userToken, nil
}

// CreateUserResetToken resets user password and creates a token to let existing user to change it
func (s *AuthServer) CreateUserResetToken(req services.CreateUserResetRequest) (services.UserToken, error) {
	err := req.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.GetUser(req.Name, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: check if some users cannot be reset
	_, err = s.ResetPassword(req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resetToken, err := s.createUserToken(services.UserTokenTypeReset, req.Name, req.TTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	url, err := formatUserTokenURL(s.publicURL(), fmt.Sprintf("/web/reset/%v", resetToken.GetName()))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resetToken.SetURL(url)

	// remove any other invite tokens for this user
	err = s.DeleteUserTokens(services.UserTokenTypeReset, req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.CreateUserToken(resetToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s.GetUserToken(resetToken.GetName())
}

func formatUserTokenURL(advertiseURL string, path string) (string, error) {
	u, err := url.Parse(advertiseURL)
	if err != nil {
		return "", trace.Wrap(err)
	}

	u.RawQuery = ""
	u.Path = path

	return u.String(), nil
}

// ResetPassword resets the user password and returns the new one
func (s *AuthServer) ResetPassword(email string) (string, error) {
	user, err := s.GetUser(email, false)
	if err != nil {
		return "", trace.Wrap(err)
	}

	password, err := utils.CryptoRandomHex(defaults.ResetPasswordLength)
	if err != nil {
		return "", trace.Wrap(err)
	}

	err = s.UpsertPassword(user.GetName(), []byte(password))
	if err != nil {
		return "", trace.Wrap(err)
	}

	return password, nil
}

func (s *AuthServer) publicURL() string {
	proxyHost := "<proxyhost>:3080"
	proxies, err := s.GetProxies()
	if err != nil {
		log.Errorf("Unable to retrieve proxy list: %v", err)
	}

	if len(proxies) > 0 {
		proxyHost = proxies[0].GetPublicAddr()
		if proxyHost == "" {
			proxyHost = fmt.Sprintf("%v:%v", proxies[0].GetHostname(), defaults.HTTPListenPort)
			log.Debugf("public_address not set for proxy, returning proxyHost: %q", proxyHost)
		}
	}

	return fmt.Sprintf("https://" + proxyHost)
}
