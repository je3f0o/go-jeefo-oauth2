package oauth2

type IStorage interface {
  GetUser(req *Request) map[string]interface{}
  GetToken(query map[string]string) map[string]interface{}
  StoreToken(
    request *Request,
    token, owner, options map[string]interface{},
  )
  UpdateToken(old_token, new_token map[string]interface{})
  DeleteToken(token map[string]interface{})
}