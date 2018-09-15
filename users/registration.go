
package users

import (
    "fmt"
    "net/http"
    "log"
    "encoding/json"
    "io/ioutil"
    "encoding/hex"
    "time"
    "gopkg.in/mgo.v2/bson"
    _ "golang.org/x/crypto/bcrypt"
    "gitlab.com/mesha/Mnemonics/appsettings"
    "gitlab.com/mesha/Mnemonics/encryption"
    _ "github.com/skip2/go-qrcode"
    "github.com/satori/go.uuid"
    rDB "gopkg.in/gorethink/gorethink.v4"


)

//This is a struct method on struct User which checks the struct variables
// provided by the post requests on user registration

func(c *UserStruct) data() bool{

  log.Println("Entered into userstruct")
  if c.Email == ""{
    fmt.Println("Problem with Password")
        return false
  }

  switch v := interface{}(c.PhoneNumber).(type) {
      case string:
          log.Printf("Phone number excepted")
      default:
            log.Printf("unexpected type %T of user phone number", v)
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
  u2 := uuid.NewV4()
  c.UserID = u2.String()
  return
}



func (c *UserStruct) GeneratePassword() string {
    salt := encryption.GenerateRandomSalt(8)
    passphrase := encryption.GenerateRandomString(8)

    password, err := encryption.GenerateScryptKey(salt, []byte(passphrase))
    if err != nil {
          log.Printf("There is an error generating the password %s", err)
          panic(err)
    }
    log.Printf("This is the password %s", hex.EncodeToString(password))
    return hex.EncodeToString(password)
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
          err = json.Unmarshal(data, &userStruct) //address needs to be passed, If you wont pass a pointer,
                                            // A copy will be created
          if err != nil {
              panic(err.Error())
               }

          //Creating a new instance of response object so that response can be returned in JSON
          if userStruct.data() == false{
                  fmt.Println("Incomplete json data")
                  json.NewEncoder(w).Encode(&appsettings.AppResponse{"Missing parameters",
                    false, true, nil})
                  return http.StatusUnauthorized, nil
          }
          session := appContext.Db.Copy()
          defer session.Close()

          rethinkdbSession := appContext.RethinkSession

          rethinkdbSettings:= *appContext.Config.Get("rethinkdb")
          rethinkDBName, _ := rethinkdbSettings.Get("database").String()
          tableName, _ := rethinkdbSettings.Get("secretTable").String()



          databaseSettings:= *appContext.Config.Get("Mongo")
          databaseName, _ := databaseSettings.Get("DBname").String()
          userCollectionName, _ := databaseSettings.Get("userCollection").String()
          secretCollectionName, _ := databaseSettings.Get("secretCollection").String()

          hsmKeysCollectionName, _ := databaseSettings.Get("hsmKeysCollection").String()

          log.Printf("This is the dbName %s", databaseName)


          userCollection := session.DB(databaseName).C(userCollectionName)
          //userKeyCollection := session.DB("feynmen_main_db").C("user_keys")
          secretCollection := session.DB(databaseName).C(secretCollectionName)
          hsmSecretCollection := session.DB(databaseName).C(hsmKeysCollectionName)

          dberr := userCollection.Find(bson.M{"email": userStruct.Email}).One(&userStruct)



          if dberr != nil {
                //This will update the User struct with user id
                userStruct.UserTime() //updates user struct with time stamp at which the user is created
                userStruct.Generateuuid() //Updates the password with bcrypt of password
                userPassword := userStruct.GeneratePassword()

                //This will generate address from encryption.address.go file and add to user struct in Address map.


                Keys := encryption.BipKeys{}
                entropy, _ := Keys.GenerateEntropy(256)
                //log.Printf("This is the entropy generated %s", entropy)
                mnemonic, _ := Keys.GenerateMnemonic(entropy)

                seed := Keys.GenerateSeed(mnemonic, []byte(""))
                rootPrivateKey, rootPublicKey := Keys.RootKeyGenerator(seed)
                log.Printf("Root Private key %s", rootPrivateKey)
                log.Printf("Root Public key %s", rootPublicKey)

                nthChildPrivate, nthChildPublic, err := Keys.GeneratePrivateChildKey(rootPrivateKey, 0)
                if err != nil{
                    log.Println("")

                }
                log.Printf("0th index Private key  is  %s", hex.EncodeToString(nthChildPrivate.Key))
                log.Printf("0th index Public key  is  %s", hex.EncodeToString(nthChildPublic.Key))

                //log.Printf("This is the menmonic generated %s", mnemonic)

                //passphrase, _ := Keys.GeneratePassphrase(16, 16)
                //log.Printf("This is the passphrase generated %s", hex.EncodeToString(passphrase))

                //Using empty string as the passphrase for generating Mnemonic from the Seed
                //seed := Keys.GenerateSeed(mnemonic, nil)
                //log.Printf("This is the seed generated %s", hex.EncodeToString(seed))

                splitShares, err := Keys.SplitMnemonic(21, 3, mnemonic)
                if err != nil{
                    log.Printf("These are the splitshares %s", splitShares)
                }


                  g := SecretsStruct{}
                  g.SetEncryptedSecrets(userPassword, userStruct.UserID, splitShares[0:3 ] )
                  g.Address = userStruct.Address
                  g.CreatedAt = userStruct.CreatedAt
                  g.PhoneNumber = userStruct.PhoneNumber
                  g.Email = userStruct.Email
                  g.PanCard = userStruct.PanCard
                  g.ZerothPublicKey =  hex.EncodeToString(nthChildPublic.Key)
                  g.PublicKey =  hex.EncodeToString(rootPublicKey.Key)
                  userStruct.ZerothPublicKey =  hex.EncodeToString(nthChildPublic.Key)
                  userStruct.PublicKey =  hex.EncodeToString(rootPublicKey.Key)
                  //log.Printf("This is the g %s", g)
                  //err = secretCollection.Insert(bson.M{"userid": userStruct.UserID, "secret_one": encryptedKeys[0],
                  //                                      "secret_two": encryptedKeys[1],
                  //                                    "secret_three": encryptedKeys[2]})




                  err = secretCollection.Insert(g)

                  if err != nil {
                              panic(err)
                           }


                  _, err = rDB.DB(rethinkDBName).Table(tableName).Insert(g).Run(rethinkdbSession)
                  if err != nil {
                          panic(err)
                    }


                  hsmKeys := HSMSecretsStruct{}
                  hsmKeys.SetEncryptionKey()
                  hsmKeys.SetUserIdHash(userStruct.UserID)
                  hsmKeys.SetEncryptedSecrets(splitShares[3:])

                  err = userCollection.Insert(userStruct)
                  if err != nil {
                          panic(err)
                        }



                err = hsmSecretCollection.Insert(&hsmKeys)
                if err != nil {
                        panic(err)
                      }


                //var encryptionStruct encryption.Encryption = &encryption.Asymmetric{}
              response := &appsettings.AppResponse{fmt.Sprintf("User succedeed with userid %s", userStruct.UserID),
                                false, true, map[string]interface{}{"password": userPassword, "user_id": userStruct.UserID, "secrets": g.Secrets}}

              json.NewEncoder(w).Encode(response)
                return http.StatusOK, nil
              }else {
                json.NewEncoder(w).Encode(&appsettings.AppResponse{"Email id has already been registered with us ", true, false, nil})
                return http.StatusUnauthorized, nil
            }
}
