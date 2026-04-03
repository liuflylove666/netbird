package templates

import (
	_ "embed"
)

//go:embed pkce-auth-msg.html
var PKCEAuthMsgTmpl string

//go:embed mfa-totp-form.html
var MFATOTPFormTmpl string
