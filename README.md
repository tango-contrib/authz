auth
======

Auth is an authorization middleware for [Tango](https://github.com/lunny/tango), it's based on [https://github.com/hsluoyz/casbin](https://github.com/hsluoyz/casbin).

## Installation

    go get github.com/hsluoyz/auth

## Simple Example

```Go
package main

import (
	"github.com/lunny/tango"
	"github.com/hsluoyz/auth"
	"github.com/hsluoyz/casbin"
	"github.com/tango-contrib/session"
)

var (
	DefaultHasPermString  = "You have the correct permission"
)

type RBACPermAction struct {
}

func (r *RBACPermAction) Get() string {
	return DefaultHasPermString
}

func (r *RBACPermAction) POST() string {
	return DefaultHasPermString
}

func (r *RBACPermAction) PUT() string {
	return DefaultHasPermString
}

func main() {
	t := tango.Classic()

	// init session middleware to store roles
	sessions := session.New()
	t.Use(sessions)

	// init auth middleware
	e := casbin.Enforcer{}
	e.Init(rbac_model.conf, rbac_policy.csv)

	t.Use(auth.Auth(e, sessions))

	// define the routers
	t.Post("/resource1", new(RBACPermAction))
	t.Any("/resource2", new(RBACPermAction))
	t.Run()
}
```

## Getting Help

- [casbin](https://github.com/hsluoyz/casbin)

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.
