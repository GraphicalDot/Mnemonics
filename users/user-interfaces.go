
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



type User struct{
    Password string `json:"password"`
    UserID string `json:"userid"`
    Address string `json:"address"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"createdate"`
    PhoneNumber string `json:"phonenumber"`
    PanCard string `json:"pancard"`
    Details map[string]string `json:"details"`
}

type Credentials struct{
    UserID *string `json:"username"`
    Password *string `json:"password"`
}
