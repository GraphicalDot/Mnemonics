


package encryption


import (
    "github.com/tyler-smith/go-bip39"
    "github.com/tyler-smith/go-bip32"
    b64 "encoding/base64"
    //"golang.org/x/crypto/nacl/secretbox"
    //"crypto/rand"
    //"io"
    "log"
    	"encoding/hex"
      //"github.com/codahale/sss"
"github.com/SSSaaS/Sssa-golang"

)


type Entropier interface{
    //The generate netropy function will take an int, for which
    // number of bytes entropy bytes will be generated
    GenerateEntropy(numberOfBytes int)([]byte, error)
}

type Mnemonicer interface {
    GenerateMnemonic(entropy []byte) (string, error)
}

type Passphraser interface{
    GeneratePassphrase(saltBytes int, passphraseBytes int) ([]byte, error)
}

type Seeder interface{
    GenerateSeed(mnemonic string, passphrase []byte) ([]byte)
}

type RootKeyGenerator interface {
      GenerateRootKeys(seed []byte) (*bip32.Key, *bip32.Key)
}

type ChildPublicKeyGenerator interface {
      GeneratePublicChildKey(rootPrivateKey *bip32.Key, childNumber uint32)(*bip32.Key, error)
}

type ChildPrivateKeyGenerator interface {
      GeneratePrivateChildKey(rootPulicKey *bip32.Key, childNumber uint32)(*bip32.Key, *bip32.Key, error)
}

type MnemonicSplitter interface {
    SplitMnemonic(number int, threshold int, mnemonic string)([]string, error)
}


type HexKeyEncoder interface {
      HexKeyEncoding(extendedKey *bip32.Key)(string)

}


type BipKeyer interface{
    Entropier
    Mnemonicer
    Passphraser
    RootKeyGenerator
    ChildPublicKeyGenerator
    ChildPrivateKeyGenerator
    HexKeyEncoder
    MnemonicSplitter
}


type BipKeys struct {
    Entropy []byte
    Mnemonic string
    Passphrase []byte
    Seed []byte
    MnemonicShares []string
    RootPublicExtendedKey *bip32.Key
    RootPrivateExtendedKey *bip32.Key
    RootPrivateHexKey string

}

func(instance *BipKeys) GenerateEntropy(numberOfBytes int)([]byte, error){
    entropy, err := bip39.NewEntropy(numberOfBytes)
    if err != nil {
      log.Printf("There is some error generating entropy %s", err)
    }
    return entropy, err
}

func (instance *BipKeys) GenerateMnemonic(entropy []byte) (string, error){
    mnemonic, err := bip39.NewMnemonic(entropy)
    if err != nil {
        log.Printf("Some error in generating Mnemonic %s", err)

}
    return mnemonic, err
}

func (instance *BipKeys) GeneratePassphrase(saltBytes int, passphraseBytes int) ([]byte, error){
    salt := GenerateRandomSalt(8)
    passphrase := GenerateRandomString(8)

    password, err := GenerateScryptKey(salt, []byte(passphrase))
      return password, err
}

func (instance *BipKeys) GenerateSeed(mnemonic string, passphrase []byte) ([]byte){
    seed := bip39.NewSeed(mnemonic, string(passphrase))
    return seed
}

func (instance *BipKeys) RootKeyGenerator(seed []byte) (*bip32.Key, *bip32.Key){
  rootPrivateKey, _ := bip32.NewMasterKey(seed)
  rootPublicKey := rootPrivateKey.PublicKey()
  return rootPrivateKey, rootPublicKey
}

func (instance *BipKeys) GeneratePublicChildKey(rootPublicKey *bip32.Key, childNumber uint32)(*bip32.Key, error){
    key, err := rootPublicKey.NewChildKey(childNumber)
    if err!= nil{
        log.Printf("There is an error in creating %s key from private key", childNumber)

    }

    return key, err


}

func (instance *BipKeys) GeneratePrivateChildKey(rootPrivateKey *bip32.Key, childNumber uint32)(*bip32.Key, *bip32.Key, error){
    key, err := rootPrivateKey.NewChildKey(childNumber)
    if err!= nil{
        log.Printf("There is an error in creating %s key from private key", childNumber)
    }
    return key, key.PublicKey(), err
}



func (instance *BipKeys) SplitMnemonic(number int, threshold int, mnemonic string)([]string, error){
      keys, err := sssa.Create(threshold, number, mnemonic)
      return keys, err
}

func (instance *BipKeys) HexKeyEncoding(extendedKey *bip32.Key)(string){
      hexKey := hex.EncodeToString(extendedKey.Key)
      return hexKey
}



type Asymmetric struct{
    RippedHexKey string
    RootMnemonic string
}





func NewMnemonic()(string) {
    //Returns a string which is 12 word mnemonic generated
    entropy, _ := bip39.NewEntropy(256)
    mnemonic, _ := bip39.NewMnemonic(entropy)
    return mnemonic
}


func NewSeed(mnemonic string)(string, []byte) {
    passphrase := GenerateRandomString(32)
    seed := bip39.NewSeed(mnemonic, passphrase)
    return passphrase, seed
}

func RootKeys(seed []byte) (*bip32.Key, *bip32.Key){
    //Generates root keys from the seed
    rootPrivateKey, _ := bip32.NewMasterKey(seed)
    rootPublicKey := rootPrivateKey.PublicKey()
    return rootPrivateKey, rootPublicKey
}



func GenerateNthKey(privateKey *bip32.Key, n uint32) (*bip32.Key, *bip32.Key) {
      //Generate nth index keys from the root keys
      key, err := privateKey.NewChildKey(n)
      if err!= nil{
          log.Printf("There is an error in creating %s key from private key", n)

      }
      return key, key.PublicKey()
}


func Encodeb64Key(key *bip32.Key) string{
    encodedKey := b64.StdEncoding.EncodeToString(key.Key)
    return encodedKey
}



func Bip32HexKey(key *bip32.Key) string{
    encodedKey := hex.EncodeToString(key.Key)
    return encodedKey
}







func (c *Asymmetric) KeysFromMnemonic(){
  seed := bip39.NewSeed(c.RootMnemonic, "abstracted")

  rootPrivateKey, _ := bip32.NewMasterKey(seed)
  //rootPublicKey := rootPrivateKey.PublicKey()
  hexkey := Bip32HexKey(rootPrivateKey)

  //log.Printf("THis is the hex endoded bip32 key %s", rootPrivateKey)

  c.RippedHexKey = hexkey
  return


}

func (c *Asymmetric) GenerateMnemonic(passphrase string) (*bip32.Key, *bip32.Key, string, string){
      //Remember the passphrase would have great effect in getting the resulting master KeysfromMnemonic
      //Eventually on every child key.
      //What we can do is, we can store passphrase on the server and Mnemonic lies with the user.
      entropy, _ := bip39.NewEntropy(256)

      //log.Println("This is the hex encoded entropy %s", hex.EncodeToString(entropy))
      mnemonic, _ := bip39.NewMnemonic(entropy)

      //log.Printf("This is the menmonic %s", mnemonic)
      //log.Printf("This is the roort passphrase %s", hex.EncodeToString([]byte(c.RootPassphrase)))

      //RIght now we are not using passphrase
      log.Printf("This is the passphrase %s", passphrase)
      seed := bip39.NewSeed(mnemonic, passphrase)

      rootPrivateKey, _ := bip32.NewMasterKey(seed)
      rootPublicKey := rootPrivateKey.PublicKey()

      //log.Printf("Root Private key is %s", rootPrivateKey)
      //log.Printf("Root Public key is %s", rootPublicKey)


      // Display mnemonic and keys
      //c.RootMnemonic = mnemonic
      //Use this to generate a child key
      //key, _ := rootPrivateKey.NewChildKey(0)
      //log.Printf("Private key 0 is %s", key)
      //log.Printf("Public key 0 is %s", key.PublicKey())
      bkey := Encodeb64Key(rootPrivateKey)
      hexkey := Bip32HexKey(rootPrivateKey)

      //log.Printf("THis is the hex endoded bip32 key %s", rootPrivateKey)

      c.RippedHexKey = hexkey
      c.RootMnemonic = mnemonic

      log.Printf("THis is the base64 endoded 32 bit ROOT key %s", bkey)
      log.Printf("THis is the hex endoded 32 ROOT bit key %s", hexkey)
      return rootPrivateKey, rootPublicKey, hexkey, mnemonic

    	// You must use a different nonce for each message you encrypt with the
    	// same key. Since the nonce here is 192 bits long, a random value
    	// provides a sufficiently small probability of repeats.


    }
