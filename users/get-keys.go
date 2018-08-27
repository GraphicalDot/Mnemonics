
package users

import (
    "fmt"
    "net/http"
    "log"
    "encoding/json"
    "io/ioutil"
    "gopkg.in/mgo.v2/bson"
    "gitlab.com/mesha/Mnemonics/appsettings"
    "github.com/davecgh/go-spew/spew"



  )




func GetKeys(appContext *appsettings.AppContext, w http.ResponseWriter, r *http.Request) (int, error){

          //Reading response data from the api
          data, err := ioutil.ReadAll(r.Body)
          defer r.Body.Close()

          //If there is an error reading the request params, The code will panic,
          // You can handle the panic by using function closures as is handled in
          //user login
          if err != nil {panic(err)}

          //Creating an instance of User struct and Unmarshalling incoming
          // json into the User staruct instance



          var request  KeyRequest
          var user UserStruct
          err = json.Unmarshal(data, &request) //address needs to be passed, If you wont pass a pointer,
                                            // A copy will be created
          if err != nil {
              panic(err.Error())
               }

          spew.Dump(request)

          log.Printf(request.Email)
          session := appContext.Db.Copy()
          defer session.Close()

          databaseSettings:= *appContext.Config.Get("Mongo")
          databaseName, _ := databaseSettings.Get("DBname").String()
          userCollectionName, _ := databaseSettings.Get("userCollection").String()
          userCollection := session.DB(databaseName).C(userCollectionName)
          secretCollectionName, _ := databaseSettings.Get("secretCollection").String()
          secretsCollection := session.DB(databaseName).C(secretCollectionName)



          dberr := userCollection.Find(bson.M{"email": request.Email, "phone_number": request.PhoneNumber}).One(&user)
          if dberr != nil {
                json.NewEncoder(w).Encode(&appsettings.AppResponse{"User doesnt exists", true, false, nil})
                return http.StatusOK, nil
            }
          spew.Dump(user)

          var secrets SecretsStruct

          dberr = secretsCollection.Find(bson.M{"user_id": user.UserID}).One(&secrets)
          if dberr != nil {
                json.NewEncoder(w).Encode(&appsettings.AppResponse{"User secrets doesnt exists", true, false, nil})
                return http.StatusOK, nil
            }

          spew.Dump(secrets)



          /*
          //Creating a new instance of response object so that response can be returned in JSON
          if userStruct.data() == false{
                  fmt.Println("Incomplete json data")
                  json.NewEncoder(w).Encode(&appsettings.AppResponse{"Missing parameters",
                    false, true, nil})
                  return http.StatusUnauthorized, nil
          }
          session := appContext.Db.Copy()
          defer session.Close()

          databaseSettings:= *appContext.Config.Get("Mongo")
          databaseName, _ := databaseSettings.Get("DBname").String()
          userCollectionName, _ := databaseSettings.Get("userCollection").String()
          secretCollectionName, _ := databaseSettings.Get("secretCollection").String()




          if dberr != nil {
            json.NewEncoder(w).Encode(&appsettings.AppResponse{"User doesnt exists", true, false, nil})
            return http.StatusOK, nil
              }


          log.Printf("This is the dbName %s", databaseName)
          */
          result := map[string]interface{}{"secret_one": secrets.SecretOne, "secret_two": secrets.SecretTwo, "secret_three": secrets.SecretThree}

          response := &appsettings.AppResponse{fmt.Sprintf("User succedeed with userid %s", "tatti"), false, true, result}

          json.NewEncoder(w).Encode(response)
            return http.StatusOK, nil
}
