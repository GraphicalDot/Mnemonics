package main

import (
	"bytes"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"gitlab.com/mesha/Mnemonics/appsettings"
	"gitlab.com/mesha/Mnemonics/encryption"
	"gitlab.com/mesha/Mnemonics/users"
	"io/ioutil"
	"log"
	    "github.com/davecgh/go-spew/spew"
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

		log.Printf("TEsting AES encryption and Decryption")
		salt := encryption.GenerateRandomSalt(8)
    passphrase := encryption.GenerateRandomString(8)

    aesKey, err := encryption.GenerateScryptKey(salt, []byte(passphrase))

		if err != nil {
					log.Printf("There is an error generating the password %s", err)
		}
		log.Printf("This is the AES Key %s", hex.EncodeToString(aesKey))
		plainText := "I am the smartest person alive, I will become what i deserve"
		log.Printf("THis is the text for operation %s", plainText)

		cipherText, err := encryption.AESEncryption(aesKey, []byte(plainText))
		log.Printf("CipherText bytes :: %s", cipherText)
		log.Printf("Hex Encoded CipherText :: %s", hex.EncodeToString(cipherText))

		decryptedText, err := encryption.DecryptBlock(cipherText, aesKey)

		if err != nil{
			log.Printf("error occurred in Decrypting CipherText :: %s", err)


		}

		spew.Dump(decryptedText)
		log.Printf("Decrypted CipherText :: %s", decryptedText)


		//file, fileerror := os.Open("settings/config.json")

		j, _ := ioutil.ReadFile("config.json")
		configfile, _ := simplejson.NewFromReader(bytes.NewReader(j))
		router := mux.NewRouter()

		context := appsettings.AppContext{Db: appsettings.Initdb(configfile), Config: configfile}


		//This function generates a random string everytime the app restarts,
		// This is the jwt secret which will be encoded in JWT token
		secret := encryption.GenerateRandomString(32)
		context.Config.Get("JWT").Set("secret", secret)


		fmt.Println("Starting the application...")


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




		log.Fatal(http.ListenAndServe(":8001", handlers.CORS()(handlers.LoggingHandler(os.Stdout, router))))

}
