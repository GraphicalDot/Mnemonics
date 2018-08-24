
package users

import (
    "fmt"
    "log"
    "time"
    "net/http"
    "io/ioutil"
    "encoding/json"
    "gopkg.in/mgo.v2/bson"
    "github.com/dgrijalva/jwt-go"
    "gitlab.com/mesha/Mnemonics/appsettings"
)

// Error represents a handler error. It provides methods for a HTTP status
// code and embeds the built-in error interface.
type Error interface {
	error
	Status() int
}

// StatusError represents an error with an associated HTTP status code.
type StatusError struct {
	Code int
	Err  error
}

// Allows StatusError to satisfy the error interface.
func (se StatusError) Error() string {
	return se.Err.Error()
}

// Returns our HTTP status code.
func (se StatusError) Status() int {
	return se.Code
}



func(c *Credentials) data() bool{
  if c.UserID == nil{
        fmt.Println("Problem with the UserID")
        return false
  }
  if c.Password == nil{
        fmt.Println("Problem with Password")
        return false
  }
  return true
}



func Userlogin(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    /*
    defer func() {
      if r := recover(); r != nil {
          http.Error(w, "Invalid post paramteres", http.StatusBadRequest)
    }
    }()
    */
        log.Println("Entered into the Userlogi")
        session := appcontext.Db.Copy()
        defer session.Close()



        data, err := ioutil.ReadAll(r.Body)
        if err != nil {panic(err)}

        var userCredentials Credentials
        err = json.Unmarshal(data, &userCredentials) //address needs to be passed, If you wont pass a pointer,
                                            // A copy will be created
        if err != nil {
            panic(err.Error())
	           }


        c := session.DB("feynmen_main_db").C("users")
        user := new(UserStruct)
        dberr := c.Find(bson.M{"userid": userCredentials.UserID}).One(&user)



        if dberr != nil {
          json.NewEncoder(w).Encode(&appsettings.AppResponse{"User doesnt exists", true, false, nil})
          return http.StatusOK, nil
            }



        if userCredentials.data() == false{
          json.NewEncoder(w).Encode(&appsettings.AppResponse{"Error with parametres", true, false, nil})
          return http.StatusOK, nil



        } else {
            asecret := *appcontext.Config.Get("JWT")
            secret, _ := asecret.Get("secret").String()

            log.Printf("This is the secret %s", secret)
            var mySigningKey = []byte(secret)
            token := jwt.New(jwt.SigningMethodHS256)
            //A map to store our claims
            claims := token.Claims.(jwt.MapClaims)
            /*Set token claims */
            claims["userid"] =  userCredentials.UserID
            claims["exp"] = time.Now().Add(time.Hour*12).Unix()
            tokenString, _ := token.SignedString(mySigningKey)
            log.Printf("This is the tokenstring %s", tokenString)

            json.NewEncoder(w).Encode(&appsettings.AppLoginResponse{"login successful", false, true, string(tokenString)})
            return http.StatusOK, nil


          }




}
