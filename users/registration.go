
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
    //"gopkg.in/mgo.v2/bson"
    _ "golang.org/x/crypto/bcrypt"
    "gitlab.com/mesha/Mnemonics/appsettings"
    "gitlab.com/mesha/Mnemonics/encryption"
    _ "github.com/skip2/go-qrcode"
    "github.com/satori/go.uuid"
    //rDB "gopkg.in/gorethink/gorethink.v4"
    "github.com/tyler-smith/go-bip32"



)

//This is a struct method on struct User which checks the struct variables
// provided by the post requests on user registration

func(c *UserStruct) data() (error, bool){

  log.Println("Entered into userstruct")
  if c.Email == ""{
    fmt.Println("Problem with Email")
        return errors.New("Problem with Email"),  false
  }

  if c.FirstName == ""{
        fmt.Println("Problem with first_name, cannot be left blank")
        return errors.New("Problem with first_name, cannot be left blank"), false
  }

  if c.LastName == ""{
        fmt.Println("Problem with last_name, cannot be left blank")
        return errors.New("Problem with last_name, cannot be left blank"), false
  }

  if c.Adhaar == ""{
        fmt.Println("Problem with adhaar, cannot be left blank")
        return errors.New("Problem with adhaar, cannot be left blank"), false
  }

  switch v := interface{}(c.PhoneNumber).(type) {
      case string:
          log.Printf("Phone number accepted")
      default:
            log.Printf("unexpected type %T of user phone number", v)
            return errors.New("Problem with adhaar_card, cannot be left blank"), false
      }
  if c.PhoneNumber == ""{
        fmt.Println("Problem with Phone number")
        return errors.New("Problem with Phone number, cannot be left blank"), false
  }
  if c.PanCard == ""{
        fmt.Println("Problem with PanCard")
        return errors.New("Problem with pancard, cannot be left blank"), false
  }

  return nil, true

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


func Bip32ToHex(key *bip32.Key) string {
    serializedPublicKey, err := key.Serialize()
    if err != nil{
        log.Printf("Error in serializeing the key %s", err)
    }
    HexRootPublicKey := hex.EncodeToString(serializedPublicKey)
    return HexRootPublicKey
}



func FromMnemonic(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){

      data, err := ioutil.ReadAll(r.Body)
      defer r.Body.Close()

      //If there is an error reading the request params, The code will panic,
      // You can handle the panic by using function closures as is handled in
      //user login
      if err != nil {panic(err)}

      //Creating an instance of User struct and Unmarshalling incoming
      // json into the User staruct instance
      var mnemonicStruct GenerateMnemonic
      err = json.Unmarshal(data, &mnemonicStruct) //address needs to be passed, If you wont pass a pointer,
                                        // A copy will be created
      if err != nil {
          panic(err.Error())
           }

      Keys := encryption.BipKeys{}
      log.Println(mnemonicStruct.Mnemonic)

      seed := Keys.GenerateSeed(mnemonicStruct.Mnemonic, []byte(""))
      rootPrivateKey, rootPublicKey := Keys.RootKeyGenerator(seed)
      log.Printf("Root Private key %s", rootPrivateKey)
      log.Printf("Root Public key %s", rootPublicKey)



      //HexRootPublicKey := Bip32ToHex(rootPublicKey)


      //log.Printf("Here the is key.key root public %s", hex.EncodeToString(rootPublicKey.Key))
      //log.Println(hex_serialized_key)

      //dese, err := hex.DecodeString(hex_serialized_key)
      //dude, err := bip32.Deserialize(dese)
      //log.Printf("Here is the recovered desrialized key %s", dude)
      //log.Printf("Here is the recovered desrialized key %s", dude.Key)

      nthChildPrivate, nthChildPublic, err := Keys.GeneratePrivateChildKey(rootPrivateKey, 0)
      if err != nil{
          log.Println("")

      }
      log.Printf("0th index Private key  is  %s", hex.EncodeToString(nthChildPrivate.Key))
      log.Printf("0th index Public key  is  %s", hex.EncodeToString(nthChildPublic.Key))

      //HexChildPublicKey := Bip32ToHex(nthChildPublic)
      mnemonicStruct.MasterPublicKey = hex.EncodeToString(rootPublicKey.Key)
      mnemonicStruct.MasterPrivateKey = hex.EncodeToString(rootPrivateKey.Key)

      mnemonicStruct.ZerothPublicKey = hex.EncodeToString(nthChildPublic.Key)
      mnemonicStruct.ZerothPrivateKey = hex.EncodeToString(nthChildPrivate.Key)

      var inInterface map[string]interface{}
      inrec, _ := json.Marshal(mnemonicStruct)
      json.Unmarshal(inrec, &inInterface)

      response := &appsettings.AppResponse{fmt.Sprintf("Nothing new"),
                        false, true, inInterface}

      json.NewEncoder(w).Encode(response)
        return http.StatusOK, nil


}




func GetMnemonic(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
      Keys := encryption.BipKeys{}
      entropy, _ := Keys.GenerateEntropy(256)
      //log.Printf("This is the entropy generated %s", entropy)
      mnemonic, _ := Keys.GenerateMnemonic(entropy)
      log.Println(mnemonic)

      seed := Keys.GenerateSeed(mnemonic, []byte(""))
      rootPrivateKey, rootPublicKey := Keys.RootKeyGenerator(seed)
      log.Printf("Root Private key %s", rootPrivateKey)
      log.Printf("Root Public key %s", rootPublicKey)



      //HexRootPublicKey := Bip32ToHex(rootPublicKey)


      //log.Printf("Here the is key.key root public %s", hex.EncodeToString(rootPublicKey.Key))
      //log.Println(hex_serialized_key)

      //dese, err := hex.DecodeString(hex_serialized_key)
      //dude, err := bip32.Deserialize(dese)
      //log.Printf("Here is the recovered desrialized key %s", dude)
      //log.Printf("Here is the recovered desrialized key %s", dude.Key)

      nthChildPrivate, nthChildPublic, err := Keys.GeneratePrivateChildKey(rootPrivateKey, 0)
      if err != nil{
          log.Println("")

      }
      log.Printf("0th index Private key  is  %s", hex.EncodeToString(nthChildPrivate.Key))
      log.Printf("0th index Public key  is  %s", hex.EncodeToString(nthChildPublic.Key))

      //HexChildPublicKey := Bip32ToHex(nthChildPublic)
      var mnemonicStruct GenerateMnemonic
      mnemonicStruct.Mnemonic = mnemonic
      mnemonicStruct.MasterPublicKey = hex.EncodeToString(rootPublicKey.Key)
      mnemonicStruct.MasterPrivateKey = hex.EncodeToString(rootPrivateKey.Key)

      mnemonicStruct.ZerothPublicKey = hex.EncodeToString(nthChildPublic.Key)
      mnemonicStruct.ZerothPrivateKey = hex.EncodeToString(nthChildPrivate.Key)

      var inInterface map[string]interface{}
      inrec, _ := json.Marshal(mnemonicStruct)
      json.Unmarshal(inrec, &inInterface)

      response := &appsettings.AppResponse{fmt.Sprintf("Nothing new"),
                        false, true, inInterface}

      json.NewEncoder(w).Encode(response)
        return http.StatusOK, nil


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
          err, _ = userStruct.data()
          if err != nil{
                  errString :=  fmt.Sprintf("%v", err)
                  json.NewEncoder(w).Encode(&appsettings.AppResponse{errString,
                    false, true, nil})
                  return http.StatusUnauthorized, nil
          }


          /*
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
                log.Println(mnemonic)

                seed := Keys.GenerateSeed(mnemonic, []byte(""))
                rootPrivateKey, rootPublicKey := Keys.RootKeyGenerator(seed)
                log.Printf("Root Private key %s", rootPrivateKey)
                log.Printf("Root Public key %s", rootPublicKey)



                HexRootPublicKey := Bip32ToHex(rootPublicKey)


                //log.Printf("Here the is key.key root public %s", hex.EncodeToString(rootPublicKey.Key))
                //log.Println(hex_serialized_key)

                //dese, err := hex.DecodeString(hex_serialized_key)
                //dude, err := bip32.Deserialize(dese)
                //log.Printf("Here is the recovered desrialized key %s", dude)
                //log.Printf("Here is the recovered desrialized key %s", dude.Key)

                nthChildPrivate, nthChildPublic, err := Keys.GeneratePrivateChildKey(rootPrivateKey, 0)
                if err != nil{
                    log.Println("")

                }
                log.Printf("0th index Private key  is  %s", hex.EncodeToString(nthChildPrivate.Key))
                log.Printf("0th index Public key  is  %s", hex.EncodeToString(nthChildPublic.Key))

                HexChildPublicKey := Bip32ToHex(nthChildPublic)

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
                  g.CreatedAt = userStruct.CreatedAt
                  g.PhoneNumber = userStruct.PhoneNumber
                  g.Email = userStruct.Email
                  g.PanCard = userStruct.PanCard
                  g.FirstName = userStruct.FirstName
                  g.LastName = userStruct.LastName
                  g.Adhaar= userStruct.Adhaar
                  g.ZerothPublicKey =  hex.EncodeToString(nthChildPublic.Key)
                  g.SerializedZerothPublicKey =  HexRootPublicKey

                  g.PublicKey =  hex.EncodeToString(rootPublicKey.Key)
                  g.SerializedPublicKey = HexChildPublicKey

                  userStruct.ZerothPublicKey =  hex.EncodeToString(nthChildPublic.Key)
                  userStruct.SerializedZerothPublicKey =  HexChildPublicKey

                  userStruct.PublicKey =  hex.EncodeToString(rootPublicKey.Key)
                  userStruct.SerializedPublicKey = HexRootPublicKey

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
            }
            */
            return http.StatusUnauthorized, nil


}
