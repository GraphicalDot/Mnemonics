
package encryption

import (
    "golang.org/x/crypto/bcrypt"
    "log"
)


func BcryptHash(text string) string {

    // Use GenerateFromPassword to hash & salt pwd.
    // MinCost is just an integer constant provided by the bcrypt
    // package along with DefaultCost & MaxCost.
    // The cost can be any value you want provided it isn't lower
    // than the MinCost (4)
    hash, err := bcrypt.GenerateFromPassword([]byte(text), bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
    // GenerateFromPassword returns a byte slice so we need to
    // convert the bytes to a string and return it
    log.Printf("This is the bcrypt hash implementation of the password %s", string(hash))
    return string(hash)
}
