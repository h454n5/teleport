/*
Copyright 2020 Gravitational, Inc.

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

package services

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// UserToken represents a temporary token used to create and reset a user
type UserToken interface {
	// Resource provides common resource properties
	Resource
	// GetUser returns User
	GetUser() string
	// GetHOTP returns HOTP
	GetHOTP() []byte
	// GetQRCode returns QRCode
	GetQRCode() []byte
	// GetOTPKey returns OTP key
	GetOTPKey() string
	// GetCreated returns Created
	GetCreated() time.Time
	// GetURL returns URL
	GetURL() string
	// SetURL returns URL
	SetURL(string)
	// CheckAndSetDefaults checks and set default values for any missing fields.
	CheckAndSetDefaults() error
}

// UserTokenV3 is an invite token spec format V3
type UserTokenV3 struct {
	// Kind is a resource kind - always resource.
	Kind string `json:"kind"`

	// SubKind is a resource sub kind
	SubKind string `json:"sub_kind,omitempty"`

	// Version is a resource version.
	Version string `json:"version"`

	// Metadata is metadata about the resource.
	Metadata Metadata `json:"metadata"`

	// Spec is a spec of the invite token
	Spec UserTokenSpecV3 `json:"spec"`
}

// GetName returns Name
func (u *UserTokenV3) GetName() string {
	return u.Metadata.Name
}

// GetUser returns User
func (u *UserTokenV3) GetUser() string {
	return u.Spec.User
}

// GetHOTP returns HOTP
func (u *UserTokenV3) GetHOTP() []byte {
	return []byte(u.Spec.HOTP)
}

// GetOTPKey returns OTP Key
func (u *UserTokenV3) GetOTPKey() string {
	return u.Spec.OTPKey
}

// GetQRCode returns QRCode
func (u *UserTokenV3) GetQRCode() []byte {
	return []byte(u.Spec.QRCode)
}

// GetCreated returns Created
func (u *UserTokenV3) GetCreated() time.Time {
	return u.Spec.Created
}

// GetURL returns URL
func (u *UserTokenV3) GetURL() string {
	return u.Spec.URL
}

// SetURL sets URL
func (u *UserTokenV3) SetURL(url string) {
	u.Spec.URL = url
}

// Expiry returns object expiry setting
func (u *UserTokenV3) Expiry() time.Time {
	return u.Metadata.Expiry()
}

// SetExpiry sets object expiry
func (u *UserTokenV3) SetExpiry(t time.Time) {
	u.Metadata.SetExpiry(t)
}

// SetTTL sets Expires header using current clock
func (u *UserTokenV3) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	u.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata
func (u *UserTokenV3) GetMetadata() Metadata {
	return u.Metadata
}

// GetVersion returns resource version
func (u *UserTokenV3) GetVersion() string {
	return u.Version
}

// GetKind returns resource kind
func (u *UserTokenV3) GetKind() string {
	return u.Kind
}

// SetName sets the name of the resource
func (u *UserTokenV3) SetName(name string) {
	u.Metadata.Name = name
}

// GetResourceID returns resource ID
func (u *UserTokenV3) GetResourceID() int64 {
	return u.Metadata.ID
}

// SetResourceID sets resource ID
func (u *UserTokenV3) SetResourceID(id int64) {
	u.Metadata.ID = id
}

// GetSubKind returns resource sub kind
func (u *UserTokenV3) GetSubKind() string {
	return u.SubKind
}

// SetSubKind sets resource subkind
func (u *UserTokenV3) SetSubKind(s string) {
	u.SubKind = s
}

// CheckAndSetDefaults checks and set default values for any missing fields.
func (u UserTokenV3) CheckAndSetDefaults() error {
	return u.Metadata.CheckAndSetDefaults()
}

// UserTokenSpecV3 is a spec for invite token
type UserTokenSpecV3 struct {
	// User is user name associated with this token
	User string `json:"user"`
	// HOTP is a secret value of one time password secret generator
	HOTP string `json:"hotp,omitempty"`
	// OTPKey is is a secret value of one time password secret generator
	OTPKey string `json:"opt_key,omitempty"`
	// QRCode is a QR code value
	QRCode string `json:"qr_code,omitempty"`
	// Created holds information about when the token was created
	Created time.Time `json:"created"`
	// URL is this token URL
	URL string `json:"url"`
}

// NewUserToken is a convenience wa to create a RemoteCluster resource.
func NewUserToken(tokenID string) UserTokenV3 {
	return UserTokenV3{
		Kind:    KindUserToken,
		Version: V3,
		Metadata: Metadata{
			Name:      tokenID,
			Namespace: defaults.Namespace,
		},
	}
}

// UserTokenSpecV3Template is a template for V3 UserToken JSON schema
const UserTokenSpecV3Template = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
		"user": {
			"type": ["string"]
		},
		"hotp": {
			"type": ["string"]
		},
		"opt_key": {
			"type": ["string"]
		},
		"qr_code": {
			"type": ["string"]
		},
		"created": {
			"type": ["string"]
		},
		"url": {
			"type": ["string"]
		}
  }
}`

// UnmarshalUserToken unmarshals UserToken
func UnmarshalUserToken(bytes []byte) (UserToken, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	schema := fmt.Sprintf(V2SchemaTemplate, MetadataSchema, UserTokenSpecV3Template, DefaultDefinitions)

	var usertoken UserTokenV3
	err := utils.UnmarshalWithSchema(schema, &usertoken, bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}

	return &usertoken, nil
}

// MarshalUserToken marshals role to JSON or YAML.
func MarshalUserToken(usertoken UserToken, opts ...MarshalOption) ([]byte, error) {
	return utils.FastMarshal(usertoken)
}
