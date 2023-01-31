package oauth2

import "crypto/rand"

const (
  seed = "abcdefghijklmnopqrstuvwxyz" +
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
         "0123456789" +
         "!@^*-_+.?;~"
  seed_length    = len(seed)
  default_length = 64
)

func TokenGenerator(options map[string]interface{}) func() string {
  length := default_length
  if options["length"] != nil {
    length = options["length"].(int)
  }

  return func() string {
    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil { panic(err) }

    result := make([]byte, length)
    for i, v := range b {
      j := int(v) % seed_length
      result[i] = seed[j]
    }
    return string(result)
  }
}