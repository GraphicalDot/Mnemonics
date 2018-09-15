

package encryption


import (
    "log"
    "net/http"
    "strconv"
    "gitlab.com/mesha/Mnemonics/appsettings"
        "encoding/json"
        "encoding/hex"
        "io/ioutil"
        "github.com/davecgh/go-spew/spew"
)


func MasterMnemonicKeys(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    data, err := ioutil.ReadAll(r.Body)
    defer r.Body.Close()
    if err != nil {panic(err)}
    var bipKeys BipKeys
    err = json.Unmarshal(data, &bipKeys) //address needs to be passed, If you wont pass a pointer,
                                      // A copy will be created
    if err != nil {
        panic(err.Error())
         }

    if bipKeys.Mnemonic == ""{
                      json.NewEncoder(w).Encode(&appsettings.AppResponse{"Mnemonic field cannot be left empty",
                        false, true, nil})
                      return http.StatusUnauthorized, nil
    }


    seed := bipKeys.GenerateSeed(bipKeys.Mnemonic, []byte(""))
    rootPrivateKey, rootPublicKey := bipKeys.RootKeyGenerator(seed)

    result := map[string]interface{}{"master_private_key": hex.EncodeToString(rootPrivateKey.Key), "master_public_key": hex.EncodeToString(rootPublicKey.Key) }
    json.NewEncoder(w).Encode(&appsettings.AppResponse{"Hex Encoded Master Keys", true, false, result})
    return http.StatusOK, nil

}




type ChildMnemonicKeysStruct struct{
    Mnemonic string `json:"mnemonic"`
    ChildKeyIndex uint32 `json:"child_key_index"`

}

type KeysIndexesMnemonicStruct struct{
    Mnemonic string `json:"mnemonic"`
    KeyIndexes []uint32 `json:"key_indexes"`

}


func(c *ChildMnemonicKeysStruct) DataValidation() (string, bool){
  if c.Mnemonic == ""{
        return "Mnemonic field cant be left empty", false
  }
  if c.ChildKeyIndex < 0{
        return "Please specify the child index number", false
  }
  return "", true
}



func(c *KeysIndexesMnemonicStruct) DataValidation() (string, bool){
    if c.Mnemonic == ""{
          return "Mnemonic field cant be left empty", false
    }

    switch v := interface{}(c.KeyIndexes).(type) {

    case []uint32:
        log.Println("Stringer:", v)

        return "", true

      default:
        return "Must be array of strings", false

}
}



func ChildMnemonicKeys(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    data, err := ioutil.ReadAll(r.Body)
    defer r.Body.Close()
    if err != nil {panic(err)}
    var child ChildMnemonicKeysStruct
    err = json.Unmarshal(data, &child) //address needs to be passed, If you wont pass a pointer,
                                      // A copy will be created
    if err != nil {
        panic(err.Error())
         }

    if message, ok := child.DataValidation(); !ok{
                 json.NewEncoder(w).Encode(&appsettings.AppResponse{message,
                   false, true, nil})
                 return http.StatusUnauthorized, nil
         }

    var bipKeys BipKeys
    seed := bipKeys.GenerateSeed(child.Mnemonic, []byte(""))
    rootPrivateKey, rootPublicKey := bipKeys.RootKeyGenerator(seed)


    nthChildPrivate, nthChildPublic, err := bipKeys.GeneratePrivateChildKey(rootPrivateKey, child.ChildKeyIndex)
    if err != nil{
        log.Println("")

    }


    result := map[string]interface{}{"master_private_key": hex.EncodeToString(rootPrivateKey.Key),
            "master_public_key": hex.EncodeToString(rootPublicKey.Key),
            "index": child.ChildKeyIndex,
            "child_private_key": hex.EncodeToString(nthChildPrivate.Key),
            "child_public_key": hex.EncodeToString(nthChildPublic.Key)}

    spew.Dump(child)
    json.NewEncoder(w).Encode(&appsettings.AppResponse{"Hex Encoded Strings", true, false, result})


    return http.StatusOK, nil



}




func KeysFromIndexes(appcontext *appsettings.AppContext, w http.ResponseWriter, r *http.Request)(int, error){
    //This is the mthod to get public keys from the indexes,
    //Arguments in request
    //    Mnemonic
    //    key_indexes
    //          An array for the indexes, the indexes will be a array of string.
    //result
    //      an array wiht dictionaries

    data, err := ioutil.ReadAll(r.Body)
    defer r.Body.Close()
    if err != nil {panic(err)}
    var child KeysIndexesMnemonicStruct
    err = json.Unmarshal(data, &child) //address needs to be passed, If you wont pass a pointer,
                                      // A copy will be created
    if err != nil {
        panic(err.Error())
         }

    if message, ok := child.DataValidation(); !ok{
                 json.NewEncoder(w).Encode(&appsettings.AppResponse{message,
                   false, true, nil})
                 return http.StatusUnauthorized, nil
         }

    var bipKeys BipKeys

    //Alotting for type map[string]interface{} witht helenght equal to thekey iundexes generated
    //by the user till now
    result := make(map[string]interface{}, len(child.KeyIndexes))

    //Generating seed from the users menmonic
    seed := bipKeys.GenerateSeed(child.Mnemonic, []byte(""))
    //Generating rooot provate key and the public key
    rootPrivateKey, _ := bipKeys.RootKeyGenerator(seed)


    for _, index := range child.KeyIndexes{
        nthChildPrivate, nthChildPublic, err := bipKeys.GeneratePrivateChildKey(rootPrivateKey, index)
        if err != nil{
            log.Println("")
          }

        var s = strconv.FormatUint(uint64(index), 10)
        result[s] = map[string]interface{}{
                  "public_key": nthChildPublic,
                  "private_key": nthChildPrivate,
            }

    }

    spew.Dump(child)
    json.NewEncoder(w).Encode(&appsettings.AppResponse{"Child public private keys based on the indexes", true, false, result})


    return http.StatusOK, nil



}
