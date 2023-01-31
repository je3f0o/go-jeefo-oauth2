package oauth2

type Request struct {
  Method  string
  Path    string
  Query   map[string][]string
  Headers map[string][]string
  Body    map[string]interface{}
}