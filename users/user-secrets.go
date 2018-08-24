
//Deals with storing the split keys of the users into the database
//A mnemonic will be generated and and its secrets wil be created based on shamir secret sharing scehme
// THe user secrets will be encrypted with the password of the user

package users

import (
    "log"
    "encoding/hex"
    "gitlab.com/mesha/Mnemonics/encryption"
)


func (c *SecretsStruct) SetEncryptedSecrets(key string, userId string, splitShares []string){
    encryptedKeys := make([][]byte, len(splitShares))

    decodePassword, decodeErr := hex.DecodeString(key)
    if decodeErr != nil{
        log.Printf("There is an error decoding the hex password %s", decodeErr)
    }


    var err error
    for index, splitKey := range splitShares{
        encryptedKeys[index], err = encryption.AESEncryption(decodePassword, []byte(splitKey))
        if err != nil{
            log.Printf("Error occurred in encrypting SplitKeys %s", err)
      }}

      c.UserID = userId
      c.SecretOne = hex.EncodeToString(encryptedKeys[0])
      c.SecretTwo = hex.EncodeToString(encryptedKeys[1])
      c.SecretThree = hex.EncodeToString(encryptedKeys[2])
      log.Printf("This is the c %s", c)
}
