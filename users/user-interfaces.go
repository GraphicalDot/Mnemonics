
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
    Password []byte `json:"password"`
    UserID string `json:"userid"`
    Address string `json:"address"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"createdate"`
    PhoneNumber string `json:"phonenumber"`
    PanCard string `json:"pancard"`
    Details map[string]string `json:"details"`

}

type SecretsStruct struct {
  UserID string `json:"userid"`
  secretOne []byte `json:secret_one`
  secretTwo []byte `json:secret_two`
  secretThree []byte `json:secret_three`
}

type HSMSecretsStruct struct {
  UserID string `json:"userid"`
  secretFour []byte `json:secret_four`
  secretFive []byte `json:secret_five`
  secretSix []byte `json:secret_six`
}





type Credentials struct{
    UserID *string `json:"username"`
    Password *string `json:"password"`
}
