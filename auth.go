package rbac

import (
	"fmt"
	"github.com/hsluoyz/casbin/api"
	"github.com/lunny/tango"
	"github.com/tango-contrib/session"
)

var (
	DefaultUserSessionKey = "casbin_user"
	DefaultNoPermString   = "You have no permission to visit this page"
	DefaultHasPermString  = "You have the correct permission"
)

// Auth return a casbin handler.
func Auth(enforcer *api.Enforcer, sessions *session.Sessions) tango.HandlerFunc {
	return func(ctx *tango.Context) {
		sub := sessions.Session(ctx.Req(), ctx.ResponseWriter).Get(DefaultUserSessionKey).(string)
		obj := ctx.Req().URL.Path
		act := ctx.Req().Method
		fmt.Println("Enforcing request:", sub, ",", obj, ",", act)

		if enforcer.Enforce(sub, obj, act) {
			ctx.Next()
		} else {
			ctx.Write([]byte(DefaultNoPermString))
		}
	}
}
