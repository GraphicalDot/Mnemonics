# Mnemonics

 r = requests.post("http://localhost:8001/registration",  data=json.dumps({"email": faker.email(), "phonenumber": faker.phone_number()}))

 {'message': 'User succedeed with userid 1293f38e-1b64-4f0e-a18a-b6f5f735f3fb',
 'error': False,
 'success': True,
 'Data': None}


databse entry will be :
{'_id': ObjectId('5b7f094e90b41a055087b5ef'),
 'password': '',
 'userid': '7437d4fc-5828-438e-ac73-0e4bba21a1c0',
 'address': '',
 'email': 'fcampbell@harrington.com',
 'createdat': datetime.datetime(2018, 8, 23, 19, 21, 49, 618000),
 'phonenumber': '1-813-717-3758x60699',
 'pancard': '',
 'details': {}}
