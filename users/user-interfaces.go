
package users

import "time"

type Response struct{
    Message string `json:"message"`
    Error bool `json:"error"`
    Success bool `json:"success"`
    Data interface{} `json:"data"`
    Token string `json:"token"`
}


type RequesterError interface{
    data() bool
}




type User struct{
    Username string `json:"username"`
    Password string `json:"password"`
    UserId string `json:"userid"`
    Address string `json:"address"`
    Email string `json:"email"`
    CreatedAt time.Time `json:"createdate"`
    PhoneNumber string `json:"phonenumber"`

}







type Credentials struct{
    Username *string `json:"username"`
    Password *string `json:"password"`

}

type UserService interface {
  CreateUser(u *User) error
  GetByUsername(username string) (*User, error)
}
