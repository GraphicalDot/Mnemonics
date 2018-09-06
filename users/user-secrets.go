
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
    encryptedKeys := make([]string, len(splitShares))

    decodePassword, decodeErr := hex.DecodeString(key)
    if decodeErr != nil{
        log.Printf("There is an error decoding the hex password %s", decodeErr)
    }


    for index, splitKey := range splitShares{
        encryptedShare, err := encryption.AESEncryption(decodePassword, []byte(splitKey))
        if err != nil{
            log.Printf("Error occurred in encrypting SplitKeys %s", err)
        }
        encryptedKeys[index] = hex.EncodeToString(encryptedShare)
        }

      c.UserID = userId
      c.Secrets = encryptedKeys
}
