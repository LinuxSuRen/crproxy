package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daocloud/crproxy/logger"
	"github.com/docker/distribution/registry/api/errcode"
)

type Generator struct {
	authFunc     func(r *http.Request, userinfo *url.Userinfo) (Attribute, bool)
	logger       logger.Logger
	tokenEncoder *Encoder
}

func NewGenerator(
	tokenEncoder *Encoder,
	authFunc func(r *http.Request, userinfo *url.Userinfo) (Attribute, bool),
	logger logger.Logger,
) *Generator {
	return &Generator{
		authFunc:     authFunc,
		logger:       logger,
		tokenEncoder: tokenEncoder,
	}
}

func (g *Generator) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errcode.ServeJSON(rw, errcode.ErrorCodeUnsupported)
		return
	}

	query := r.URL.Query()
	account := query.Get("account")
	scope := query.Get("scope")
	service := query.Get("service")

	t := Token{
		Service: service,
		Scope:   scope,
		Account: account,
	}

	if scope != "" {
		scopeSlice := strings.SplitN(scope, ":", 4)
		if len(scopeSlice) != 3 {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect scope"))
			return
		}

		if scopeSlice[2] != "pull" {
			errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(fmt.Sprintf("Unsupported scope %q", scopeSlice[2])))
			return
		}

		t.Image = scopeSlice[1]
	}

	if g.authFunc == nil {
		t.Anonymous = true
	} else {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			attribute, login := g.authFunc(r, nil)
			if !login {
				if scope == "" {
					errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect user or password"))
				} else {
					errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect user or password, please try logging in again"))
				}
				return
			}
			t.Attribute = attribute
			return
		} else {
			auth := strings.SplitN(authorization, " ", 2)
			if len(auth) != 2 {
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect authorization"))
				return
			}
			switch auth[0] {
			case "Basic":
				user, pass, ok := parseBasicAuth(auth[1])
				if user == "" {
					errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("User required"))
					return
				}

				if account != user {
					errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect user"))
					return
				}

				var u *url.Userinfo
				if ok {
					u = url.UserPassword(user, pass)
				} else {
					u = url.User(user)
				}

				attribute, login := g.authFunc(r, u)
				if !login {
					if scope == "" {
						errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect user or password"))
					} else {
						errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage("Incorrect user or password, please try logging in again"))
					}
					return
				}
				t.Attribute = attribute
			default:
				errcode.ServeJSON(rw, errcode.ErrorCodeDenied.WithMessage(fmt.Sprintf("Unsupported authorization %q", authorization)))
				return
			}
		}
	}

	rw.Header().Set("Content-Type", "application/json")

	now := time.Now()
	expiresIn := 10

	t.ExpiresAt = now.Add((time.Duration(expiresIn) + 1) * time.Second)

	code, err := g.tokenEncoder.Encode(t)
	if err != nil {
		if g.logger != nil {
			g.logger.Println("Error encoding token", err)
		}
		errcode.ServeJSON(rw, errcode.ErrorCodeUnknown)
		return
	}

	json.NewEncoder(rw).Encode(tokenInfo{
		Token:     code,
		ExpiresIn: int64(expiresIn),
		IssuedAt:  now,
	})
}

type tokenInfo struct {
	Token     string    `json:"token,omitempty"`
	ExpiresIn int64     `json:"expires_in,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}