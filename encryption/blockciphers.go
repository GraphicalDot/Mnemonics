


package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
    "log"
)





func EncryptBlock(plaintext []byte) ([]byte, []byte, error) {
    /*
    key := make([]byte, 32)

    _, err := rand.Read(key)
    if err != nil {
        log.Printf("Error ocurred in generating AES key %s", err)
       // handle error here
     }

    log.Printf("This is the AES key %s", key)
    */
    key, err := GeneratePBKFD2key()

    if err != nil {
        log.Printf("Error ocurred in generating PBKDF2 key AES key %s", err)
        return nil, nil, err
    }


    c, err := aes.NewCipher(key)
    if err != nil {
      log.Printf("Error ocurred in generating AES key %s", err)
        return nil, nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
      log.Printf("Error ocurred in generating AES key %s", err)
        return nil, nil, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), key, nil
}

func DecryptBlock(ciphertext []byte, key []byte) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
