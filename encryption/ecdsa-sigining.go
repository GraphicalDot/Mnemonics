

package encryption

//THe methods here deals with the ecdsa sigining functions
import (
    "crypto/rand"
    "crypto/ecdsa"
    "log"
    "crypto/elliptic"
    "crypto/x509"
  "encoding/pem"
  "encoding/base64"
"errors"
)

func GenerateECDSAKeys()(*ecdsa.PrivateKey, *ecdsa.PublicKey){
    privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

   	if err != nil {
   		log.Println(err)
   		panic(err)
   	}

   	publicKey := &privateKey.PublicKey
    return privateKey, publicKey
}


func EncryptedpemToECDSAKey(pemData []byte, password string) ([]byte, error) {
    // Convert it to pem

    block, _ := pem.Decode(pemData)
    if block == nil {
		      log.Printf("bad key data: %s", "not PEM-encoded")
          return nil, errors.New("Bad key data: Not Pem Encoded")

        }

    if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
    		log.Printf("unknown key type %q, want %q", got, want)
        return nil, errors.New("Chutiya")

    }


    der, err := x509.DecryptPEMBlock(block, []byte(password))
    if err != nil {
           log.Printf("Decrypt failed: %v", err)
           return nil, err

       }


    return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der}), err
}


func ECDSAToEncryptedPem(privateKey *ecdsa.PrivateKey, pwd string) (string, error) {

    password, err := base64.StdEncoding.DecodeString(pwd)
    if err != nil {
      return "", err
    }

    x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
    block := &pem.Block{
        Type:  "ECDSA PRIVATE KEY",
        Bytes: x509Encoded,
    }
    // Encrypt the pem
    if pwd != "" {
        block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
        if err != nil {
            return "", err
        }
    }

    return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block)), nil
}

//Converts a *ecdsa.PublicKey to pem encoded string format
func PublicECDSAtoPEM(publicKey *ecdsa.PublicKey) string{

  x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
  pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: x509EncodedPub})

  return base64.StdEncoding.EncodeToString(pemEncodedPub)
}


//Converts a pem encoded ECDSA public key back to *ecdsa.PublicKey
func PEMToPublicECDSA(pemEncodedPub string) (*ecdsa.PublicKey){

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
    publicKey := genericPublicKey.(*ecdsa.PublicKey)

    return publicKey
}
