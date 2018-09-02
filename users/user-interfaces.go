
package users

import ("time"
  _ "github.com/satori/go.uuid"
)



type Response struct{
    Message string `json:"message"`
    Error bool `json:"error"`
    Success bool `json:"success"`
    Data interface{} `json:"data"`
    Token string `json:"token"`
}

type KeyRequest struct{
    Email string `json:"email"`
    PhoneNumber string `bson:"phone_number" json:"phone_number"`
}





type UserStruct struct{
    UserID string `bson:"user_id" json:"user_id"`
    Address string `json:"address"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"created_at"`
    PhoneNumber string `bson:"phone_number" json:"phone_number"`
    PanCard string `json:"pancard"`
    Details map[string]string `json:"details"`
    Salt string `json:"salt"`
    Phash string `json:"phash"`
}

type SecretsStruct struct {
  UserID string `bson:"user_id" json:"userid"`
  Secrets []string `r:"secrets" bson:"secret_three" json:secret_three`
}

type HSMSecretsStruct struct {
  UseridHash string `bson:"user_id_hash" json:"user_id_hash"`
  AESKey string `bson:"aes_key" json:"aes_key"`
  Secrets []string `bson:"secrets" json:secrets`
}







type Credentials struct{
    UserID *string `bson:"user_id" json:"username"`
    Password *string `json:"password"`
}
