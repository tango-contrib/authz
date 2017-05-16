authz [![Build Status](https://travis-ci.org/tango-contrib/authz.svg?branch=master)](https://travis-ci.org/tango-contrib/authz) [![Coverage Status](https://coveralls.io/repos/github/tango-contrib/authz/badge.svg?branch=master)](https://coveralls.io/github/tango-contrib/authz?branch=master) [![GoDoc](https://godoc.org/github.com/tango-contrib/authz?status.svg)](https://godoc.org/github.com/tango-contrib/authz)
======

authz is an authorization middleware for [Tango](https://github.com/lunny/tango), it's based on [https://github.com/hsluoyz/casbin](https://github.com/hsluoyz/casbin).

## Installation

    go get github.com/tango-contrib/authz

## Simple Example

```Go
package main

import (
	"github.com/hsluoyz/casbin"
	"github.com/lunny/tango"
	"github.com/tango-contrib/authz"
	"github.com/tango-contrib/session"
)

func main() {
	tg := tango.Classic()
	sessions := session.New()

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set("casbin_user", "user's name")
		ctx.Next()
	}))

	// load the casbin model and policy from files, database is also supported.
	e := casbin.NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	tg.Use(authz.Auth(&e, sessions))
	
	// define the routers
	// the access that is denied by authz will return "You have no permission to visit this page"
	tg.Any("*", func() string {
	    // the access is permitted when got here
		return "You have the correct permission"
	})

	tg.Run()
}
```

## Getting Help

- [casbin](https://github.com/hsluoyz/casbin)

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.
