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
		fmt.Println(configfile)
		router := mux.NewRouter()

		context := appsettings.AppContext{Db: appsettings.Initdb(configfile), Config: configfile}

		//This function generates a random string everytime the app restarts,
		// This is the jwt secret which will be encoded in JWT token
		secret, _ := encryption.GenerateRandomString(32)
		log.Printf("This is the secret %s", secret)
		context.Config.Get("JWT").Set("secret", secret)

		fmt.Printf("THis is the secret %s", secret)

		fmt.Println("Starting the application...")


		UserLoginContextHandler := &appsettings.ContextHandler{&context, users.Userlogin}
		userCheckAuth := appsettings.CheckAuth(UserLoginContextHandler, &context)
		router.Methods("POST").Path("/login").Name("Userlogin").Handler(userCheckAuth)


		RegistrationContextHandler := &appsettings.ContextHandler{&context, users.UserRegistration}
		router.Methods("POST").Path("/registration").Name("Registration").Handler(RegistrationContextHandler)

		MnemonicContextHandler := &appsettings.ContextHandler{&context, encryption.GenerateMnemonic}
		mnemonicCheckAuth := appsettings.CheckAuth(MnemonicContextHandler, &context)
		router.Methods("POST").Path("/generatemnemonic").Name("GenerateMnemonic").Handler(mnemonicCheckAuth)



		log.Fatal(http.ListenAndServe(":8001", handlers.CORS()(handlers.LoggingHandler(os.Stdout, router))))

}
