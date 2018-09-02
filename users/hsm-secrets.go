

package users

import (
    "log"
    "encoding/hex"
    "gitlab.com/mesha/Mnemonics/encryption"
"golang.org/x/crypto/blake2b"
)










func (c *HSMSecretsStruct) SetEncryptionKey(){
  salt := encryption.GenerateRandomSalt(8)
  passphrase := encryption.GenerateRandomString(8)

  aesKey, err := encryption.GenerateScryptKey(salt, []byte(passphrase))
  if err != nil {
        log.Printf("There is an error generating the AES key for encryption SharedKeys%s", err)
  }
  c.AESKey = hex.EncodeToString(aesKey)
}



func (c *HSMSecretsStruct) SetUserIdHash(userid string) {
    hasher, _ := blake2b.New256([]byte(userid))
    hash := hasher.Sum(nil)
    c.UseridHash = hex.EncodeToString(hash)
}


func (c *HSMSecretsStruct) SetEncryptedSecrets(splitKeys []string){
    encryptedKeys := make([][]byte, len(splitKeys))

    decodeAesKey, decodeErr := hex.DecodeString(c.AESKey)
    if decodeErr != nil{
        log.Printf("There is an error decoding the HSMAES Key %s", decodeErr)
    }

    for index, splitKey := range splitKeys {
        encryptedShare, err := encryption.AESEncryption(decodeAesKey, []byte(splitKey))

          encryptedKeys[index] = hex.EncodeToString(encryptedShare)
        if err != nil{
            log.Printf("Error occurred in encrypting SplitKeys %s", err)
      }}
    c.Secrets = encryptedKeys
    log.Printf("This is the c %s", c)
}
