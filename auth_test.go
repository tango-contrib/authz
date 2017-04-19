package rbac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hsluoyz/casbin/api"
	"github.com/lunny/tango"
	"github.com/tango-contrib/session"
	"github.com/hsluoyz/casbin/persist"
	"github.com/hsluoyz/casbin/util"
)

func testEnforce(t *testing.T, e *api.Enforcer, sub string, obj string, act string, res bool) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultUserSessionKey, sub)
		ctx.Next()
	}))

	tg.Use(Auth(e, sessions))
	tg.Any("*", func() string {
		return DefaultHasPermString
	})

	req, err := http.NewRequest(act, "http://localhost:8000"+obj, nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	if res {
		expect(t, buff.String(), DefaultHasPermString)
	} else {
		expect(t, buff.String(), DefaultNoPermString)
	}
}

func TestBasicModel(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "/resource1", "GET", true)
	testEnforce(t, e, "alice", "/resource1", "POST", false)
	testEnforce(t, e, "alice", "/resource2", "GET", false)
	testEnforce(t, e, "alice", "/resource2", "POST", false)
	testEnforce(t, e, "bob", "/resource1", "GET", false)
	testEnforce(t, e, "bob", "/resource1", "POST", false)
	testEnforce(t, e, "bob", "/resource2", "GET", false)
	testEnforce(t, e, "bob", "/resource2", "POST", true)
}

func TestBasicModelWithRoot(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/basic_model_with_root.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "/resource1", "GET", true)
	testEnforce(t, e, "alice", "/resource1", "POST", false)
	testEnforce(t, e, "alice", "/resource2", "GET", false)
	testEnforce(t, e, "alice", "/resource2", "POST", false)
	testEnforce(t, e, "bob", "/resource1", "GET", false)
	testEnforce(t, e, "bob", "/resource1", "POST", false)
	testEnforce(t, e, "bob", "/resource2", "GET", false)
	testEnforce(t, e, "bob", "/resource2", "POST", true)
	testEnforce(t, e, "root", "/resource1", "GET", true)
	testEnforce(t, e, "root", "/resource1", "POST", true)
	testEnforce(t, e, "root", "/resource2", "GET", true)
	testEnforce(t, e, "root", "/resource2", "POST", true)
}

func TestRBACModel(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/rbac_model.conf", "examples/rbac_policy.csv")

	testEnforce(t, e, "alice", "/resource1", "GET", true)
	testEnforce(t, e, "alice", "/resource1", "POST", false)
	testEnforce(t, e, "alice", "/resource2", "GET", false)
	testEnforce(t, e, "alice", "/resource2", "POST", false)
	testEnforce(t, e, "alice", "/resource3", "GET", true)
	testEnforce(t, e, "alice", "/resource3", "POST", false)
	testEnforce(t, e, "bob", "/resource1", "GET", false)
	testEnforce(t, e, "bob", "/resource1", "POST", false)
	testEnforce(t, e, "bob", "/resource2", "GET", false)
	testEnforce(t, e, "bob", "/resource2", "POST", true)
	testEnforce(t, e, "bob", "/resource3", "GET", true)
	testEnforce(t, e, "bob", "/resource3", "POST", false)
}

func TestRBACModelWithResourceRoles(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/rbac_model_with_resource_roles.conf", "examples/rbac_policy_with_resource_roles.csv")

	testEnforce(t, e, "alice", "/resource1", "GET", true)
	testEnforce(t, e, "alice", "/resource1", "POST", true)
	testEnforce(t, e, "alice", "/resource2", "GET", false)
	testEnforce(t, e, "alice", "/resource2", "POST", true)
	testEnforce(t, e, "bob", "/resource1", "GET", false)
	testEnforce(t, e, "bob", "/resource1", "POST", false)
	testEnforce(t, e, "bob", "/resource2", "GET", false)
	testEnforce(t, e, "bob", "/resource2", "POST", true)
}

func TestKeymatchModel(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/keymatch_model.conf", "examples/keymatch_policy.csv")

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource1", "POST", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "POST", false)
	testEnforce(t, e, "bob", "/alice_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/alice_data/resource1", "POST", false)
	testEnforce(t, e, "bob", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "bob", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "POST", true)
	testEnforce(t, e, "bob", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource2", "POST", true)
}

func testGetPolicy(t *testing.T, e *api.Enforcer, res [][]string) {
	myRes := e.GetPolicy()

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func TestDBSavePolicy(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a := persist.NewDBAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
	a.SavePolicy(e.GetModel())
}

func TestDBSaveAndLoadPolicy(t *testing.T) {
	e := &api.Enforcer{}
	e.InitWithFile("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a := persist.NewDBAdapter("mysql", "root:@tcp(127.0.0.1:3306)/")
	a.SavePolicy(e.GetModel())

	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	a.LoadPolicy(e.GetModel())
	testGetPolicy(t, e, [][]string{{"alice", "/resource1", "GET"}, {"bob", "/resource2", "POST"}, {"res3_admin", "/resource3", "GET"}})

	e = &api.Enforcer{}
	e.InitWithDB("examples/rbac_model.conf", "mysql", "root:@tcp(127.0.0.1:3306)/")
	testGetPolicy(t, e, [][]string{{"alice", "/resource1", "GET"}, {"bob", "/resource2", "POST"}, {"res3_admin", "/resource3", "GET"}})

}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
