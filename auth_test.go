package rbac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hsluoyz/casbin"
	"github.com/lunny/tango"
	"github.com/tango-contrib/session"
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

func testEnforce(t *testing.T, e *casbin.Enforcer, sub string, obj string, act string, res bool) {
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
	tg.Any("*", new(RBACPermAction))

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
	e := &casbin.Enforcer{}
	e.Init("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "/resource1", "GET", true)
	testEnforce(t, e, "alice", "/resource1", "POST", false)
	testEnforce(t, e, "alice", "/resource2", "GET", false)
	testEnforce(t, e, "alice", "/resource2", "POST", false)
	testEnforce(t, e, "bob", "/resource1", "GET", false)
	testEnforce(t, e, "bob", "/resource1", "POST", false)
	testEnforce(t, e, "bob", "/resource2", "GET", false)
	testEnforce(t, e, "bob", "/resource2", "POST", true)
}

func TestRBACModel(t *testing.T) {
	e := &casbin.Enforcer{}
	e.Init("examples/rbac_model.conf", "examples/rbac_policy.csv")

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
