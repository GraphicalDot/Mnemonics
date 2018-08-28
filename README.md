# Mnemonics

To install shamir secret library in python user this.
pip install git+git://github.com/SSSaaS/sssa-python

Other library which is required to run aes functions is pycryptodome as GCM mode is not supported by
most popular cryptography library.

The APi code is now hosted on 52.66.22.183 running behind Nginx.
```
import requests
import json
import binascii
from SSSA import sssa
from faker import Faker
from Crypto.Cipher import AES



ip_port= "52.66.22.183"

faker = Faker()

email, phone_number = faker.email(), faker.phone_number()

print (f"Trying to register user with email {email} and phone_number {phone_number}")

r = requests.post("http://%s/registration"%ip_port,  data=json.dumps({"email": email, "phone_number": phone_number, "junkone": faker.paragraph(), "junk_two": faker.paragraph()}))
user_id = r.json()["data"]["user_id"]
password = r.json()["data"]["password"]

print (f"User with user id {user_id} has been created, password is {password}")


r = requests.post("http://%s/getkeys"%ip_port,  data=json.dumps({"email": email, "phone_number": phone_number}))


print ("Hex ecndoed secrets which are received\n")
print ("Secret One")
print (r.json()["data"]["secret_one"], "\n")
print ("Secret Two")
print (r.json()["data"]["secret_two"], "\n")
print ("Secret Three")
print (r.json()["data"]["secret_three"], "\n")


shares = []



##hex decoding the password
key = binascii.unhexlify(password)
for secret in r.json()["data"].keys():
    data = binascii.unhexlify(r.json()["data"][secret])
    nonce, tag = data[:12], data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    shares.append(cipher.decrypt_and_verify(data[12:-16], tag))


print (shares)
sss = sssa()
mnemonic = sss.combine(shares)

print (mnemonic)
```

As python code for getting master private and child keys from Mnemonic is not available, For the time being
Two seperate apis have been created:
/master_mnemonic_keys
        To get the master public private key from the mnemonic

```
r = requests.post("http://%s/master_mnemonic_keys"%ip,  data=json.dumps({"mnemonic": "art distance random latin ranch canal mouse mirror whisper broom rotate door wheat toddler mirror recipe friend hill life early staff betray fit fit"}))

{'message': 'Hex Encoded Master Keys',
 'error': True,
 'success': False,
 'data': {'master_private_key': '67cbc441133a38c4f3199e44e02bb3b407eb5962ce8ad2d8ecf80b742d055acc',
  'master_public_key': '02c40d1c2499112bad49a8cf7c1d461f0dbe6037fd918d8dcf76d10d064f499ae1'}}
```

/child_mnemonic_keys
    To generate child public and private keys from the Mnemonic based on the index

```
r = requests.post("http://%s/child_mnemonic_keys"%ip,  data=json.dumps({"mnemonic": "art distance random latin ranch canal mouse mirror whisper broom rotate door wheat toddler mirror recipe friend hill life early staff betray fit fit", "child_key_index": 1}))
{'message': 'Hex Encoded Strings',
 'error': True,
 'success': False,
 'data': {'child_private_key': '13d0bf6c0be067f143dfb5cdb3dd59a57d907785f7843edd7601c5935f226e90',
  'child_public_key': '02ddfaae1da3bb18002e8682fb3c5528d270ab254b4b0083af09332b2356099bc3',
  'index': 1,
  'master_private_key': '67cbc441133a38c4f3199e44e02bb3b407eb5962ce8ad2d8ecf80b742d055acc',
  'master_public_key': '02c40d1c2499112bad49a8cf7c1d461f0dbe6037fd918d8dcf76d10d064f499ae1'}}
```

Code for converting BIP keys to standard secp256k1 key, which can be used on sawtooth network.

```
import secp256k1
private_key  = secp256k1.PrivateKey(bytes.fromhex("8f26d40638fc47c22191569fcf25b6b41fa8db2b589c7df6b42ea040ed41965c"))
```
