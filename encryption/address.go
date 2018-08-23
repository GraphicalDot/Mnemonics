


package encryption


import (
    "crypto/rsa"
    "golang.org/x/crypto/sha3"
  "github.com/akamensky/base58"
  "encoding/hex"
  	"golang.org/x/crypto/ripemd160"
  "log"

)


//calculates the adress of the user from its secret public keys
//It first calculates

func CreateAddress(publicKey interface{}) string {

      var address string
      var rsa_pem_format string
      var err error
      switch v := publicKey.(type) {
             case string:
                rsa_pem_format = publicKey.(string)
             case *rsa.PrivateKey:
               log.Println("THe rsa file is an string pem format")
                  rsa_pem_format, err = ExportRsaPublicKeyAsPemStr(publicKey.(*rsa.PublicKey))
                  if err != nil {
                    log.Printf("Here is the error while encosing public key as pem str %s", err)
                    }
             default:
                     log.Println(v)

           }

           h := sha3.New256()
           h.Write([]byte(rsa_pem_format))
           sha3_hash := hex.EncodeToString(h.Sum(nil))

           hasher := ripemd160.New()
           hasher.Write([]byte(sha3_hash))
           hashBytes := hasher.Sum(nil)

           address = base58.Encode([]byte(hashBytes))
           log.Println(address)

        return address


}
