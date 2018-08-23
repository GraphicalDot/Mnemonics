

package encryption




import (
    "golang.org/x/crypto/pbkdf2"
    "log"
    "crypto/rand"
    "crypto/sha256"
    "math/big"
    "encoding/base64"
    "encoding/hex"
    "golang.org/x/crypto/scrypt"



   //"gitlab.com/mesha/Gofeynmen/users"

)




type UserKeys struct{
    UserId string `json:"userid"`
    RSAPemPublicKey string `rsa_pem_public_key`
    RSAEncryptedPemPrivateKey string `rsa_encrypted_pem_private_key`
    SigningECDSAPemPublicKey string `signing_ecdsa_pem_public_key`
    SigningECDSAEncryptedPemPrivateKey string `signing_ecdsa_encrypted_pem_private_key`

}


type UserSecrets struct {
    UserId string `json:"userid"`
    EncryptionSalt string `json:"encryption_salt"`
    EncryptionPassphrase string `json:"encryption_passphrase"`

}

func EncrytAESKey(usersecret *UserSecrets, userkeys *UserKeys, aeskey []byte) (string, error) {
    //This function receives a UserSecret, UserKeys struct , AES Key as input,
    //returns the encrypted AES Key

    //EncryptedPEMToPrivateKey(pemData string, password string) ([]byte, error)
    //ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
    publicKey, err := ParseRsaPublicKeyFromPemStr(userkeys.RSAPemPublicKey)
    if err != nil{
        log.Printf("There is an error parsing public key from UserKeys struct to *rsa.PublicKey %s", err)
        return "", err
    }

    //Base64 encoded aes key
    cipherAESText, err := EncryptRSA(aeskey, publicKey)
    return cipherAESText, err

}


func GenerateRandomBytes(n int) (string, error) {
    	b := make([]byte, n)
    	_, err := rand.Read(b)
    	// Note that err == nil only if we read len(b) bytes.
    	if err != nil {
    		return "", err
    	}

    	return  base64.StdEncoding.EncodeToString(b), nil
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(length int) (string, error) {
      result := ""
    for {
    if len(result) >= length {
      return  base64.StdEncoding.EncodeToString([]byte(result)), nil
    }
    num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
    if err != nil {
      return "", err
    }
    n := num.Int64()
    // Make sure that the number/byte/letter is inside
    // the range of printable ASCII characters (excluding space and DEL)
    if n > 32 && n < 127 {
      result += string(n)
    }
    }
}



func GenerateScryptKey(saltBytes int, passphraseBytes int)([]byte, error){


      //entropy, _ := bip39.NewEntropy(256)

      salt := make([]byte, saltBytes)
      _, err := rand.Read(salt)
      // Note that err == nil only if we read len(b) bytes.
      if err != nil {
        return nil, err
      }

      b64salt, err := GenerateRandomBytes(passphraseBytes)

      log.Printf("This is the salt for the Scrypt %s", hex.EncodeToString(salt))
      dk, err := scrypt.Key([]byte(b64salt), salt, 32768, 8, 1, 32)
      log.Printf("This is the scrypt key %s", hex.EncodeToString(dk))

      return dk, err

}

func GeneratePBKFD2key() ([]byte, error) {

    b64salt, err := GenerateRandomBytes(8) //This generates a random byte of 8 length
                                      //Which will be used as a salt for the pbkdf2 function

    if err != nil {
        log.Printf("There was an Error generating the salt for PBkdf2 function %s", err)
        return nil, err
    }

    //Thsi generates a random pbkdf2 key from the rndom string generated
    // from the GenerateRandomString function mentioned in encryption package
    secret, _ := GenerateRandomString(32)
    log.Printf("This is the secret %s", secret)

    salt, err := base64.StdEncoding.DecodeString(b64salt)
    if err != nil {
      return nil, err
    }

    dk := pbkdf2.Key([]byte(secret), salt, 4096, 32, sha256.New)
    return dk, nil
}
