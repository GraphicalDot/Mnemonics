package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"gitlab.com/mesha/Mnemonics/appsettings"
	"gitlab.com/mesha/Mnemonics/encryption"
	"gitlab.com/mesha/Mnemonics/users"
	"io/ioutil"
	"log"
	 _  "github.com/davecgh/go-spew/spew"
	 rDB "gopkg.in/gorethink/gorethink.v4"


	"net/http"
	"os"
)

func TestHandler(c *appsettings.AppContext, w http.ResponseWriter, req *http.Request) (int, error) {
	//So in this handler we now have the context provided
	response := simplejson.New()
	response.Set("foo", "bar")
	json.NewEncoder(w).Encode(response)
	return http.StatusOK, nil
}

func main() {
		//file, fileerror := os.Open("settings/config.json")

		j, _ := ioutil.ReadFile("config.json")
		configfile, _ := simplejson.NewFromReader(bytes.NewReader(j))
		router := mux.NewRouter()


		context := appsettings.AppContext{Db: appsettings.Initdb(configfile), RethinkSession: appsettings.InitRethinkdb(configfile),  Config: configfile}


		//This function generates a random string everytime the app restarts,
		// This is the jwt secret which will be encoded in JWT token
		secret := encryption.GenerateRandomString(32)
		context.Config.Get("JWT").Set("secret", secret)


		//var err error

		/*
		session, err := rDB.Connect(rDB.ConnectOpts{
		Address:  "192.168.1.17:28015"})
		if err != nil {
				fmt.Println(err)
			}
		*/

		rethinkdbSettings:= context.Config.Get("rethinkdb")
		rethinkDBName, _ := rethinkdbSettings.Get("database").String()
		tableName, _ := rethinkdbSettings.Get("secretTable").String()
		db, err := rDB.DBCreate(rethinkDBName).RunWrite(context.RethinkSession)
					log.Printf("Error in creating database %s", db)

		_, err = rDB.DB(rethinkDBName).TableCreate(tableName).RunWrite(context.RethinkSession)
				if err != nil {
						fmt.Println(err)
		}



		UserLoginContextHandler := &appsettings.ContextHandler{&context, users.Userlogin}
		userCheckAuth := appsettings.CheckAuth(UserLoginContextHandler, &context)
		router.Methods("POST").Path("/login").Name("Userlogin").Handler(userCheckAuth)


		RegistrationContextHandler := &appsettings.ContextHandler{&context, users.UserRegistration}
		router.Methods("POST").Path("/registration").Name("Registration").Handler(RegistrationContextHandler)

		GetKeysContextHandler := &appsettings.ContextHandler{&context, users.GetKeys}
		router.Methods("POST").Path("/getkeys").Name("Getkeys").Handler(GetKeysContextHandler)

		MasterMnemonicContextHandler := &appsettings.ContextHandler{&context, encryption.MasterMnemonicKeys}
		//mnemonicCheckAuth := appsettings.CheckAuth(MnemonicContextHandler, &context)
		router.Methods("POST").Path("/master_mnemonic_keys").Name("MasterMnemonicKeys").Handler(MasterMnemonicContextHandler)


		ChildMnemonicContextHandler := &appsettings.ContextHandler{&context, encryption.ChildMnemonicKeys}
		//mnemonicCheckAuth := appsettings.CheckAuth(MnemonicContextHandler, &context)
		router.Methods("POST").Path("/child_mnemonic_keys").Name("MasterMnemonicKeys").Handler(ChildMnemonicContextHandler)


		KeysFromIndexesContextHandler := &appsettings.ContextHandler{&context, encryption.KeysFromIndexes}
		//mnemonicCheckAuth := appsettings.CheckAuth(MnemonicContextHandler, &context)
		router.Methods("POST").Path("/keys_from_indexes").Name("KeysFromIndexes").Handler(KeysFromIndexesContextHandler)




		log.Fatal(http.ListenAndServe(":8001", handlers.CORS()(handlers.LoggingHandler(os.Stdout, router))))

}
