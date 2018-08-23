
package users

import (
    "fmt"
    "net/http"
    "log"
    "encoding/json"
    "io/ioutil"
    "encoding/hex"
    "time"
    "errors"
    "gopkg.in/mgo.v2/bson"

    "golang.org/x/crypto/bcrypt"
    "golang.org/x/crypto/sha3"
    "gitlab.com/mesha/Mnemonics/appsettings"
    "gitlab.com/mesha/Mnemonics/encryption"
    _ "github.com/skip2/go-qrcode"
    "github.com/satori/go.uuid"


)

//This is a struct method on struct User which checks the struct variables
// provided by the post requests on user registration

func(c *User) data() bool{
  if c.Email == ""{
        fmt.Println("Problem with Password")
        return false
  }
  if c.PhoneNumber == ""{
        fmt.Println("Problem with Phone number")
        return false
  }
  return true

}

//This is the struct method which adds useid on the basis of sha3_256 to the
//struct User
func(c *User) UseridHash(){
  h := sha3.New256()
  h.Write([]byte(c.Email))
  _ = hex.EncodeToString(h.Sum(nil))

}


//This si the struct method which adds useid on the basis of sha3_256 to the
//struct User
func(c *User) UserTime(){
    loc, _ := time.LoadLocation("Asia/Kolkata")
    c.CreatedAt = time.Now().In(loc)
    return
}


func(c *User) Generateuuid() {
  u2 := uuid.NewV4()
  c.UserID = u2.String()
  return
}




func (c *User) HashAndSalt() {
    // Use GenerateFromPassword to hash & salt pwd.
    // MinCost is just an integer constant provided by the bcrypt
    // package along with DefaultCost & MaxCost.
    // The cost can be any value you want provided it isn't lower
    // than the MinCost (4)
    hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
    // GenerateFromPassword returns a byte slice so we need to
    // convert the bytes to a string and return it
    log.Printf("This is the bcrypt hash implementation of the password %s", string(hash))
    c.Password = string(hash)
    return
}

func (c *User) GeneratePassword(){
    password, err := encryption.GenerateScryptKey(8, 8)
    if err != nil {
          log.Printf("There is an error generating the password %s", err)
    }
    log.Printf("This is the password %s", hex.EncodeToString(password))

    c.Password = hex.EncodeToString(password)
}

func (c *User) ComparePasswords(plainPassword string) bool {
    // Since we'll be getting the hashed password from the DB it
    // will be a string so we'll need to convert it to a byte slice
    //plainPwd will also be a string
    fmt.Printf("This is the plain user password %s", plainPassword)
    plainPwd := []byte(plainPassword)
    byteHash := []byte(c.Password)
    err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
    if err != nil {
        log.Printf("Passwords didnt match %s", err)
        return false
    }

    return true
}



func UserRegistration(appContext *appsettings.AppContext, w http.ResponseWriter, r *http.Request) (int, error){

          //Reading response data from the api
          data, err := ioutil.ReadAll(r.Body)
          defer r.Body.Close()

          //If there is an error reading the request params, The code will panic,
          // You can handle the panic by using function closures as is handled in
          //user login
          if err != nil {panic(err)}

          //Creating an instance of User struct and Unmarshalling incoming
          // json into the User staruct instance
          var user User
          err = json.Unmarshal(data, &user) //address needs to be passed, If you wont pass a pointer,
                                            // A copy will be created
          if err != nil {
              panic(err.Error())
               }

          //Creating a new instance of response object so that response can be returned in JSON
          if user.data() == false{
            json.NewEncoder(w).Encode(&appsettings.AppResponse{"Missing parameters",
                    false, true, nil})
            return http.StatusNotAcceptable, errors.New("Error in POst parameteres")
          }
          session := appContext.Db.Copy()
          defer session.Close()

          databaseSettings:= *appContext.Config.Get("Mongo")
          databaseName, _ := databaseSettings.Get("DBname").String()
          userCollectionName, _ := databaseSettings.Get("userCollection").String()

          log.Printf("This is the dbName %s", databaseName)


          userCollection := session.DB(databaseName).C(userCollectionName)
          //userKeyCollection := session.DB("feynmen_main_db").C("user_keys")
          // userSecretCollection := session.DB("feynmen_main_db").C("user_secrets")

          dberr := userCollection.Find(bson.M{"userid": user.UserID}).One(&user)



          if dberr != nil {
                //This will update the User struct with user id
                user.UserTime() //updates user struct with time stamp at which the user is created
                user.Generateuuid() //Updates the password with bcrypt of password
                user.GeneratePassword()

                //This will generate address from encryption.address.go file and add to user struct in Address map.

                log.Printf("This is the user %s", user)

                err = userCollection.Insert(&user)
                if err != nil {
                        panic(err)
                      }

                Keys := encryption.BipKeys{}
                entropy, _ := Keys.GenerateEntropy(256)
                log.Printf("This is the entropy generated %s", entropy)

                mnemonic, _ := Keys.GenerateMnemonic(entropy)
                log.Printf("This is the menmonic generated %s", mnemonic)

                passphrase, _ := Keys.GeneratePassphrase(16, 16)
                log.Printf("This is the passphrase generated %s", hex.EncodeToString(passphrase))

                seed := Keys.GenerateSeed(mnemonic, passphrase)
                log.Printf("This is the seed generated %s", hex.EncodeToString(seed))

                Keys.SplitMnemonic(mnemonic)
                /*
                err = userKeyCollection.Insert(&userKeys)
                if err != nil {
                        panic(err)
                      }

                err = userSecretCollection.Insert(&userSecrets)
                if err != nil {
                      panic(err)
                    }
                  */
                //var encryptionStruct encryption.Encryption = &encryption.Asymmetric{}

                json.NewEncoder(w).Encode(&appsettings.AppResponse{fmt.Sprintf("User succedeed with userid %s", user.UserID), false, true, nil})
                return http.StatusOK, nil
              }else {
                json.NewEncoder(w).Encode(&appsettings.AppResponse{"Choose a different username", true, false, nil})
                return http.StatusUnauthorized, nil
            }
}
