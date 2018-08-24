
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
    "gitlab.com/mesha/Mnemonics/appsettings"
    "gitlab.com/mesha/Mnemonics/encryption"
    _ "github.com/skip2/go-qrcode"
    "github.com/satori/go.uuid"


)

//This is a struct method on struct User which checks the struct variables
// provided by the post requests on user registration

func(c *UserStruct) data() bool{
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

//This si the struct method which adds useid on the basis of sha3_256 to the
//struct User
func(c *UserStruct) UserTime(){
    loc, _ := time.LoadLocation("Asia/Kolkata")
    c.CreatedAt = time.Now().In(loc)
    return
}


func(c *UserStruct) Generateuuid() {
  u2, _ := uuid.NewV4()
  c.UserID = u2.String()
  return
}




func (c *UserStruct) HashAndSalt() {
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
    c.Password = hash
    return
}

func (c *UserStruct) GeneratePassword(){
    password, err := encryption.GenerateScryptKey(8, 8)
    if err != nil {
          log.Printf("There is an error generating the password %s", err)
    }
    log.Printf("This is the password %s", hex.EncodeToString(password))

    c.Password = password
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
          var userStruct  UserStruct
          log.Printf("THis is the empty user %s", userStruct)
          err = json.Unmarshal(data, &userStruct) //address needs to be passed, If you wont pass a pointer,
                                            // A copy will be created
          if err != nil {
              panic(err.Error())
               }

          //Creating a new instance of response object so that response can be returned in JSON
          if userStruct.data() == false{
            json.NewEncoder(w).Encode(&appsettings.AppResponse{"Missing parameters",
                    false, true, nil})
            return http.StatusNotAcceptable, errors.New("Error in POst parameteres")
          }
          session := appContext.Db.Copy()
          defer session.Close()

          databaseSettings:= *appContext.Config.Get("Mongo")
          databaseName, _ := databaseSettings.Get("DBname").String()
          userCollectionName, _ := databaseSettings.Get("userCollection").String()
          secretCollectionName, _ := databaseSettings.Get("secretCollection").String()

          log.Printf("This is the dbName %s", databaseName)


          userCollection := session.DB(databaseName).C(userCollectionName)
          //userKeyCollection := session.DB("feynmen_main_db").C("user_keys")
          secretCollection := session.DB(databaseName).C(secretCollectionName)

          dberr := userCollection.Find(bson.M{"email": userStruct.Email}).One(&userStruct)



          if dberr != nil {
                //This will update the User struct with user id
                userStruct.UserTime() //updates user struct with time stamp at which the user is created
                userStruct.Generateuuid() //Updates the password with bcrypt of password
                userStruct.GeneratePassword()

                //This will generate address from encryption.address.go file and add to user struct in Address map.


                Keys := encryption.BipKeys{}
                entropy, _ := Keys.GenerateEntropy(256)
                log.Printf("This is the entropy generated %s", entropy)

                mnemonic, _ := Keys.GenerateMnemonic(entropy)
                log.Printf("This is the menmonic generated %s", mnemonic)

                passphrase, _ := Keys.GeneratePassphrase(16, 16)
                log.Printf("This is the passphrase generated %s", hex.EncodeToString(passphrase))

                //Using empty string as the passphrase for generating Mnemonic from the Seed
                seed := Keys.GenerateSeed(mnemonic, nil)
                log.Printf("This is the seed generated %s", hex.EncodeToString(seed))

                splitShares, err := Keys.SplitMnemonic(6, 3, mnemonic)
                if err != nil{
                    log.Printf("These are the splitshares %s", splitShares)
                }


                encryptedKeys := make([][]byte, len(splitShares)/2)

                for index, splitKey := range splitShares[0:3] {
                    encryptedKeys[index], err = encryption.AESEncryption(userStruct.Password, []byte(splitKey))
                    if err != nil{
                        log.Printf("Error occurred in encrypting SplitKeys %s", err)
                  }}


                  err = userCollection.Insert(&userStruct)
                  if err != nil {
                          panic(err)
                        }

                  err = secretCollection.Insert(bson.M{"userid": userStruct.UserID, "secret_one": encryptedKeys[0],
                                                        "secret_two": encryptedKeys[1],
                                                      "secret_three": encryptedKeys[2]})
                        if err != nil {
                              panic(err)
                            }

                /*
                err = userKeyCollection.Insert(&userKeys)
                if err != nil {
                        panic(err)
                      }


                  */
                //var encryptionStruct encryption.Encryption = &encryption.Asymmetric{}

                json.NewEncoder(w).Encode(&appsettings.AppResponse{fmt.Sprintf("User succedeed with userid %s", userStruct.UserID), false, true, nil})
                return http.StatusOK, nil
              }else {
                json.NewEncoder(w).Encode(&appsettings.AppResponse{"Email id has already been registered with us ", true, false, nil})
                return http.StatusUnauthorized, nil
            }
}
