import httpx
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

class Reko:
    def __init__(self, url: str, auth: str, products: str, users: str, key: str, blacklist: str):
        self.url = url
        self.auth = auth
        self.products = products
        self.users = users
        self.key = key
        self.blacklist = blacklist

class Auth:
    def __init__(self, reko: Reko):
        self.reko = reko

    async def register(self, name: str, email: str, password: str):

        publicKey = await publickey(self.reko)

        encryptedEmail = publicKey.encrypt(
            email.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encryptedPassword = publicKey.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encryptedName = publicKey.encrypt(
            name.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        emailEncoded = base64.b64encode(encryptedEmail).decode('utf-8')
        passwordEncoded = base64.b64encode(encryptedPassword).decode('utf-8')
        nameEncoded = base64.b64encode(encryptedName).decode('utf-8')

        payload = {
            "name": nameEncoded,
            "email": emailEncoded,
            "password": passwordEncoded
        }
        headers = {'Content-Type': 'application/json'}
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.reko.url}{self.reko.auth}/register", data=json.dumps(payload), headers=headers)
        return response.json()

    async def login(self, email: str, password: str, hwid: str):
        publicKey = await publickey(self.reko)

        encryptedEmail = publicKey.encrypt(
            email.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encryptedPassword = publicKey.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encryptedHWID = publicKey.encrypt(
            hwid.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        emailEncoded = base64.b64encode(encryptedEmail).decode('utf-8')
        passwordEncoded = base64.b64encode(encryptedPassword).decode('utf-8')
        hwidEncoded = base64.b64encode(encryptedHWID).decode('utf-8')

        payload = {
            "email": emailEncoded,
            "password": passwordEncoded,
            "hwid": hwidEncoded
        }
        headers = {'Content-Type': 'application/json'}
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.reko.url}{self.reko.auth}/login", data=json.dumps(payload), headers=headers)
        return response.json()

class User:
    def __init__(self, reko: Reko, token: str):
        self.reko = reko
        self.token = token

    async def current(self):
        headers = {
            'auth-token': self.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.reko.url}{self.reko.users}", headers=headers)
        return response.json()
    
    async def specific(self, usernameOrEmail: str):
        headers = {
            'auth-token': self.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.reko.url}{self.reko.users}/{usernameOrEmail}", headers=headers)
        return response.json()
    
class Products:
    def __init__(self, reko: Reko, user: User):
        self.reko = reko
        self.user = user
    
    async def create(self, name:str):
        payload = {
            'name': name
        }
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.reko.url}{self.reko.products}/", headers=headers, data=json.dumps(payload))
        return response.json()
    
    async def attribute(self, productid: str, username: str):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        payload = {
            'name': username
        }
        async with httpx.AsyncClient() as client:
            response = await client.put(f"{self.reko.url}{self.reko.products}/attribute/{productid}", data=json.dumps(payload), headers=headers)
        return response.json()

    async def getAllProducts(self):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.reko.url}{self.reko.products}/", headers=headers)
        return response.json()
    
    async def getProductUsers(self, productid: str):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.reko.url}{self.reko.products}/{productid}/users", headers=headers)
        return response.json()
    
    async def addCode(self, codeValue: str, codeName: str, productid: str):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        payload = {
            "codeName": codeName,
            "codeValue": codeValue
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.reko.url}{self.reko.products}/{productid}/code", data=json.dumps(payload), headers=headers)
        return response.json()
    
    async def getCode(self, productName: str):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.reko.url}{self.reko.products}/{productName}/codes", headers=headers)
        return response.json()

class Blacklist:
    def __init__(self, reko: Reko, user: User):
        self.reko = reko
        self.user = user

    async def addUser(self, userId: str, discord: str, hwid: str, ip: str):
        headers = {
            'auth-token': self.user.token,
            'Content-Type': 'application/json'
        }
        payload = {
            'discord': discord,
            'hwid': hwid,
            'ip': ip
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(f"{self.reko.url}{self.reko.blacklist}/{userId}", data=json.dumps(payload), headers=headers)
        return response.json()
        
async def publickey(Reko: Reko):
    headers = {'Content-Type': 'application/json'}
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{Reko.url}{Reko.key}/public", headers=headers)
        data = response.json()
    keyBytes = data['key'].encode()
    return serialization.load_pem_public_key(keyBytes)
