/*
Copyright 2017-2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"fmt"
	"time"

	authority "github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	. "gopkg.in/check.v1"
)

type UserTokenTest struct {
	bk backend.Backend
	a  *AuthServer
}

var _ = fmt.Printf
var _ = Suite(&UserTokenTest{})

func (s *UserTokenTest) SetUpSuite(c *C) {
	utils.InitLoggerForTests()
}

func (s *UserTokenTest) TearDownSuite(c *C) {
}

func (s *UserTokenTest) SetUpTest(c *C) {
	var err error
	c.Assert(err, IsNil)
	s.bk, err = lite.New(context.TODO(), backend.Params{"path": c.MkDir()})
	c.Assert(err, IsNil)

	// set cluster name
	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	c.Assert(err, IsNil)
	authConfig := &InitConfig{
		ClusterName:            clusterName,
		Backend:                s.bk,
		Authority:              authority.New(),
		SkipPeriodicOperations: true,
	}
	s.a, err = NewAuthServer(authConfig)
	c.Assert(err, IsNil)

	err = s.a.SetClusterName(clusterName)
	c.Assert(err, IsNil)

	// set static tokens
	staticTokens, err := services.NewStaticTokens(services.StaticTokensSpecV2{
		StaticTokens: []services.ProvisionTokenV1{},
	})
	c.Assert(err, IsNil)
	err = s.a.SetStaticTokens(staticTokens)
	c.Assert(err, IsNil)
}

func (s *UserTokenTest) TearDownTest(c *C) {
}

func (s *UserTokenTest) TestUserResetToken(c *C) {
	username := "joe@example.com"
	pass := "pass123"
	_, _, err := CreateUserAndRole(s.a, username, []string{username})
	c.Assert(err, IsNil)

	err = s.a.UpsertPassword(username, []byte(pass))
	c.Assert(err, IsNil)

	token, err := s.a.CreateUserResetToken(username, time.Hour)
	c.Assert(err, IsNil)
	c.Assert(token.GetUser(), Equals, username)
	c.Assert(token.GetURL(), Equals, "https://<proxyhost>:3080/web/reset/"+token.GetName())

	// verify that password was reset
	err = s.a.CheckPasswordWOToken(username, []byte(pass))
	c.Assert(err, NotNil)

	// create another reset token for the same user
	token, err = s.a.CreateUserResetToken(username, time.Hour)
	c.Assert(err, IsNil)

	// previous token must be deleted
	tokens, err := s.a.GetUserTokens(username)
	c.Assert(err, IsNil)
	c.Assert(len(tokens), Equals, 1)
	c.Assert(tokens[0].GetName(), Equals, token.GetName())
}

func (s *UserTokenTest) TestCreateInviteToken(c *C) {
	role := services.NewAdminRole()
	err := s.a.UpsertRole(role)
	c.Assert(err, IsNil)

	invite := services.UserInvite{
		Name:      "son@example.com",
		ExpiresIn: time.Hour,
		CreatedBy: "mother@example.com",
		Roles:     []string{role.GetName()},
	}

	token, err := s.a.CreateInviteToken(invite)
	c.Assert(err, IsNil)
	c.Assert(token.GetUser(), Equals, invite.Name)
	c.Assert(token.GetURL(), Equals, "https://<proxyhost>:3080/web/newuser/"+token.GetName())

	// create another invite for the same user
	token, err = s.a.CreateInviteToken(invite)
	c.Assert(err, IsNil)

	// previous invite must be deleted
	tokens, err := s.a.GetUserTokens(invite.Name)
	c.Assert(err, IsNil)
	c.Assert(len(tokens), Equals, 1)
	c.Assert(tokens[0].GetName(), Equals, token.GetName())
}
