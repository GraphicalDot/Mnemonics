
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



type UserStruct struct{
    Password string `json:"password"`
    UserID string `bson:"user_id" json:"user_id"`
    Address string `json:"address"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"created_at"`
    PhoneNumber string `bson:"phone_number" json:"phone_number"`
    PanCard string `json:"pancard"`
    Details map[string]string `json:"details"`

}

type SecretsStruct struct {
  UserID string `bson:"user_id" json:"userid"`
  SecretOne string `bson:"secret_one" json:secret_one`
  SecretTwo string `bson:"secret_two" json:secret_two`
  SecretThree string `bson:"secret_three" json:secret_three`
}

type HSMSecretsStruct struct {
  UseridHash string `bson:"user_id_hash" json:"user_id_hash"`
  AESKey string `bson:"aes_key" json:"aes_key"`
  SecretFour string`bson:"secret_four" json:secret_four`
  SecretFive string `bson:"secret_five" json:secret_five`
  SecretSix string `bson:"secret_six" json:secret_six`
}





type Credentials struct{
    UserID *string `bson:"user_id" json:"username"`
    Password *string `json:"password"`
}
