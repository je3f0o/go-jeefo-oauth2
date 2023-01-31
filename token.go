package oauth2

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

type _json map[string]interface{}

type TokenContext struct {
  access_token_lifetime   int32
  refresh_token_lifetime  int32
  access_token_generator  func() string
  refresh_token_generator func() string
  IsExpired               func(t interface{}) bool
}

type key_val struct {
  key string
  val interface{}
}

const (
  SECONDS_PER_HOUR       = 60  * 60
  SECONDS_PER_DAY        = 24 * SECONDS_PER_HOUR
  access_token_lifetime  = SECONDS_PER_DAY
  refresh_token_lifetime = 0
  atl_key                = "access_token_lifetime"
  rtl_key                = "refresh_token_lifetime"
  TokensTable            = "oauth2_tokens"
)

var ErrorNotFound      = errors.New("Not found")
var ErrorInvalidGrant  = errors.New("Invalid grant")
var ErrorUnimplemented = errors.New("Unimplemented")

var lifetime_options = []key_val{
  {atl_key, int32( 90 * SECONDS_PER_DAY)},
  {rtl_key, int32(365 * SECONDS_PER_DAY)},
}

func (ctx *TokenContext) AccessTokenGenerator() string {
	return ctx.access_token_generator()
}

func (ctx *TokenContext) RefreshTokenGenerator() string {
	return ctx.refresh_token_generator()
}

func NewTokenContext(options map[string]interface{}) *TokenContext {
  var access_token_lifetime int32 = access_token_lifetime
  if v, ok := options[atl_key].(int32); ok {
    access_token_lifetime = v
  }
  if access_token_lifetime <= 0 {
    panic(fmt.Sprintf("Invalid argument: `options.%s`", atl_key))
  }

  var refresh_token_lifetime int32 = refresh_token_lifetime
  if v, ok := options[rtl_key].(int32); ok {
    refresh_token_lifetime = v
  }
  if refresh_token_lifetime < 0 {
    panic(fmt.Sprintf("Invalid argument: `options.%s`", rtl_key))
  }

  return &TokenContext{
    access_token_lifetime   : access_token_lifetime,
    access_token_generator  : token_generator(options, atl_key),
    refresh_token_lifetime  : refresh_token_lifetime,
    refresh_token_generator : token_generator(options, rtl_key),
  }
}

func (ctx *TokenContext) Token(
  req     *Request,
  storage  IStorage,
  options map[string]interface{},
) map[string]interface{} {
  switch req.Body["grant_type"] {
  case "password":
    user := storage.GetUser(req)
    if user != nil {
      owner := _json{"user": user}
      return ctx.new_token(req, storage, owner, options)
    }
    return nil
  case "refresh_token":
    refresh_token, ok := req.Body["refresh_token"].(string)
    if !ok { return nil }

    where := map[string]string{ "refresh_token": refresh_token }
    token := storage.GetToken(where)
    if token != nil {
      if ctx.IsExpired(token["refresh_token_expires_at"]) {
        storage.DeleteToken(token)
      } else {
        options := _json{
          atl_key: token[atl_key],
          rtl_key: token[rtl_key],
        }
        return ctx.renew_token(storage, token, options)
      }
    }
    return nil
  case "authorization_code":
  case "client_credentials": panic(ErrorUnimplemented)
  }
  panic(ErrorInvalidGrant)
}

func (ctx *TokenContext) renew_token(
  storage   IStorage,
  old_token, options map[string]interface{},
) map[string]interface{} {
  token := ctx.generate(options)
  storage.UpdateToken(old_token, token)
  token["type"] = old_token["type"]
  return token
}

func (ctx *TokenContext) new_token(
  req     *Request,
  storage  IStorage,
  owner, options map[string]interface{},
) map[string]interface{} {
  token := ctx.generate(options)
  storage.StoreToken(req, token, owner, options)
  return token
}

func (ctx *TokenContext) generate(
  options ...map[string]interface{},
) map[string]interface{} {
  token := map[string]interface{}{}
  for _, _type := range []string{"access", "refresh"} {
    ctx.generate_token(token, _type, options...)
  }
  return token
}

func token_generator(
  options map[string]interface{},
  key string,
) func() string {
  token_generator_options := map[string]interface{}{}
  if options[key] != nil {
    token_generator_options["length"] = options[key]
  }
  return TokenGenerator(token_generator_options)
}

func add_seconds(seconds int32) time.Time {
	t := time.Now()
	return t.Add(time.Duration(seconds) * time.Second)
}

func capitalize(s string) string {
  return strings.ToUpper(s[:1]) + s[1:]
}

func (ctx *TokenContext) generate_token(
  token map[string]interface{},
  _type string,
  options ...map[string]interface{},
) {
  key          := fmt.Sprintf("%s_token", _type)
  method       := fmt.Sprintf("%sTokenGenerator", capitalize(_type))
  expires_at   := fmt.Sprintf("%s_token_expires_at", _type)
  lifetime_key := fmt.Sprintf("%s_token_lifetime", _type)
  
  value    := reflect.ValueOf(ctx).MethodByName(method).Call(nil)
  lifetime := int32(reflect.ValueOf(*ctx).FieldByName(lifetime_key).Int())
  if len(options) > 0 {
    if v, ok := options[0][lifetime_key].(int32); ok {
      lifetime = v
    }
  }

  token[key]          = value[0].String()
  token[expires_at]   = add_seconds(lifetime)
  token[lifetime_key] = lifetime
}