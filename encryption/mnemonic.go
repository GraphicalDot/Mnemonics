

package encryption


import (
    "log"
    "net/http"
    "gitlab.com/mesha/Mnemonics/appsettings"
        "encoding/json"
        "encoding/hex"
        "io/ioutil"


)


func GenerateMnemonic(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    scryptKey, _ := GenerateScryptKey(16, 16)


    c := Asymmetric{ "", ""}
    privateKey, publicKey, hexKey, mnemonic := c.GenerateMnemonic(hex.EncodeToString(scryptKey))

    log.Printf("This is the private key that was generated %s", privateKey)
    log.Printf("This is the public key that was generated %s", publicKey)
    log.Printf("This is the HexKey key that was generated %s", hexKey)
    log.Printf("This is the Mnemonic key that was generated %s", mnemonic)
    Secrets()
    //log.Println(json.Marshal(c))
    json.NewEncoder(w).Encode(c)

    return http.StatusOK, nil

}



func KeysfromMnemonic(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    data, err := ioutil.ReadAll(r.Body)
    defer r.Body.Close()

    //If there is an error reading the request params, The code will panic,
    // You can handle the panic by using function closures as is handled in
    //user login
    if err != nil {panic(err)}

    //Creating an instance of User struct and Unmarshalling incoming
    // json into the User staruct instance
    var asymmteric Asymmetric
    err = json.Unmarshal(data, &asymmteric) //address needs to be passed, If you wont pass a pointer,
                                      // A copy will be created
    if err != nil {
        panic(err.Error())
         }

    log.Println(asymmteric)
    asymmteric.KeysFromMnemonic()
    json.NewEncoder(w).Encode(asymmteric)


    return http.StatusOK, nil


}
