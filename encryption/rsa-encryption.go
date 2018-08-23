

package encryption

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "log"
    "crypto/x509"
  "encoding/pem"
  "errors"
  "encoding/base64"

)








func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem)
}

func PrivateKeyToEncryptedPEM(privkey *rsa.PrivateKey, pwd string) (string, error) {
    // Convert it to pem
    //returns a base64 encoded key
    password, err := base64.StdEncoding.DecodeString(pwd)
    if err != nil {
      return "", err
    }
    block := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privkey),
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

func EncryptedPEMToPrivateKey(pemData string, password string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(pemData)
    if err != nil {
      return nil, err
    }
    // Convert it to pem

    block, _ := pem.Decode(data)
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




func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {

    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
    //returns base64 encoded public key
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
      log.Println(err)

            return "", err
    }
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return base64.StdEncoding.EncodeToString(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    //returns *rsa.encoded public key
    data, err := base64.StdEncoding.DecodeString(pubPEM)
    if err != nil {
      log.Printf("Error decoding base64 RSA public key %s", err)
      return nil, err
    }//receives base64 endoed string

    block, _ := pem.Decode([]byte(data))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            log.Printf("Error in parsing public RSA key  %s", err)
            return nil, err
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
          log.Println("successful retreival of RSA public key from pem string")
          log.Println(pub)
          return pub, nil
    default:
            break // fall through
    }

    return nil, errors.New("Key type is not RSA")
}




func RsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey){
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

    if err != nil {
        log.Println(err.Error())
        panic(err)
    }

    publicKey := &privateKey.PublicKey
    return privateKey, publicKey

}



func EncryptRSA(message []byte, publicKey *rsa.PublicKey) (string, error) {
    label := []byte("")
    hash := sha256.New()

    log.Printf("This is the public key %s\n", publicKey)
    log.Printf("This is the message to be encrypted %s", message)

    ciphertext, err := rsa.EncryptOAEP(
        hash,
        rand.Reader,
        publicKey,
        message,
        label,
    )

    if err != nil {
        log.Printf("THis is error while encrypting message with RSA public key %s", err)
        return "", err
    }

    return base64.StdEncoding.EncodeToString(ciphertext), nil
}


func DecryptRSA(encryptedmsg string, privateKey *rsa.PrivateKey) []byte {
    data, err := base64.StdEncoding.DecodeString(encryptedmsg)
    if err != nil{
        log.Printf("Error occurred while decoding encrypted Message in RSA %s ", err)
    }

    sha1hash := sha256.New()
    decryptedmsg, err := rsa.DecryptOAEP(sha1hash, rand.Reader, privateKey, data, []byte(""))
    if err != nil {
        log.Println(err)
        panic(err)
    }
    log.Printf("OAEP decrypted [%x] to \n[%s]\n", encryptedmsg, decryptedmsg)
    return decryptedmsg

}
