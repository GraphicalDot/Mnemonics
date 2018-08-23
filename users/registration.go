
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

)

//This is a struct method on struct User which checks the struct variables
// provided by the post requests on user registration

func(c *User) data() bool{
  if c.Username == ""{
        fmt.Println("Problem with the Username")
        return false
  }
  if c.Password == ""{
        fmt.Println("Problem with Password")
        return false
  }

  if c.Email == ""{
        fmt.Println("Problem with Password")
        return false
  }

  if c.PhoneNumber == ""{
        fmt.Println("Problem with Password")
        return false
  }
  return true

}

//This si the struct method which adds useid on the basis of sha3_256 to the
//struct User
func(c *User) UseridHash(){
  h := sha3.New256()
  h.Write([]byte(c.Email))
  sha3_hash := hex.EncodeToString(h.Sum(nil))
  c.UserId = sha3_hash
}


//This si the struct method which adds useid on the basis of sha3_256 to the
//struct User
func(c *User) UserTime(){
  c.CreatedAt = time.Now().Local()
}


func(c *User) GenerateAddress(publicKey interface{}){
    c.Address = encryption.CreateAddress(publicKey)

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
            json.NewEncoder(w).Encode(&appsettings.FeynResponse{"Missing parameters",
                    false, true, nil})
            return http.StatusNotAcceptable, errors.New("Error in POst parameteres")
          }
          session := appContext.Db.Copy()
          defer session.Close()
          userCollection := session.DB("feynmen_main_db").C("users")
          userKeyCollection := session.DB("feynmen_main_db").C("user_keys")
          userSecretCollection := session.DB("feynmen_main_db").C("user_secrets")

          dberr := userCollection.Find(bson.M{"username": user.Username}).One(&user)



          if dberr != nil {
                //This will update the User struct with user id
                user.UseridHash()//Updates userid with hash of email
                user.UserTime() //updates user struct with time stamp at which the user is created
                user.HashAndSalt() //Updates the password with bcrypt of password


                //Gnereatinh key pairs for the user
                privateRSAKey, publicRSAKey := encryption.RsaKeyPair()

                passphrase, perr := encryption.GenerateRandomString(32)

                if perr != nil{
                  log.Printf("Error in generating passphrase for encryption of private key %s", perr)
                }

                salt, salterr := encryption.GenerateRandomBytes(8)
                if salterr != nil{
                        log.Printf("Error in generating salt for encryption of private key %s", salterr)
                  }


                pemEncryptedPrivateRSAKey, _ := encryption.PrivateKeyToEncryptedPEM(privateRSAKey, passphrase) //encrypted Pem encoded string of privateRSA KEY
                pemPublicRSAKey, _ :=  encryption.ExportRsaPublicKeyAsPemStr(publicRSAKey) //Pem encoded string of public RSAKey


                privateECDSAKey, publicECDSAKey := encryption.GenerateECDSAKeys()

                pemEncryptedPrivateECDSAKey, err := encryption.ECDSAToEncryptedPem(privateECDSAKey, passphrase) //encrypted Pem encode sting of privateECDSA KEY

                pemPublicECDSAKey := encryption.PublicECDSAtoPEM(publicECDSAKey)//Pem encode sting of publicECDSA KEY

                userKeys := encryption.UserKeys{user.UserId, pemPublicRSAKey, pemEncryptedPrivateRSAKey, pemPublicECDSAKey, pemEncryptedPrivateECDSAKey}

                //BOIth passphrase and salt are base64 encoded strings
                userSecrets := encryption.UserSecrets{user.UserId, salt, passphrase}

                //This will generate address from encryption.address.go file and add to user struct in Address map.
                user.GenerateAddress(pemPublicRSAKey)


                err = userCollection.Insert(&user)
                if err != nil {
                        panic(err)
                      }
                err = userKeyCollection.Insert(&userKeys)
                if err != nil {
                        panic(err)
                      }

                err = userSecretCollection.Insert(&userSecrets)
                if err != nil {
                      panic(err)
                    }

                //var encryptionStruct encryption.Encryption = &encryption.Asymmetric{}

                json.NewEncoder(w).Encode(&appsettings.FeynResponse{fmt.Sprintf("User succedeed with userid %s", user.UserId), false, true, nil})
                return http.StatusOK, nil
              }else {
                json.NewEncoder(w).Encode(&appsettings.FeynResponse{"Choose a different username", true, false, nil})
                return http.StatusUnauthorized, nil
            }
}
