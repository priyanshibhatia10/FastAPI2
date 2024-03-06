from fastapi import HTTPException, status,Depends,Request
from passlib.context import CryptContext
import re
from dotenv import dotenv_values
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from typing import Annotated,Dict
import jwt
from models import *
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


#Password hashing
pwd_hash = CryptContext(schemes=["bcrypt"], deprecated="auto") #pwd_context

config_cred = dotenv_values(".env")
auth_pass = OAuth2PasswordBearer(tokenUrl="token") #oauth2_scheme


#Functions for Bad requests
def is_not_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if re.search(regex, email):
        return False
    else:
        return True


#hashed  password
def get_password_hash(password):
    return pwd_hash.hash(password)

#verify password
def verify_password(password, hashed_password):
    return pwd_hash.verify(password, hashed_password)  #hashed password from database

#generate token during login
def generate_token(username: str) -> Dict[str, str]:
    payload = {
        "username": username,
        "expires": None
    }
    token = jwt.encode(payload, config_cred['SECRET'], algorithm=config_cred['ALGORITHM'])
    return {
        "access_token": token
    }

#decode token for authorisation
def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, config_cred['SECRET'], algorithm=config_cred['ALGORITHM'])
        return decoded_token
    except:
        return None

#Token Vefication for current user
def verify_token(token: str,current_user:str):
    decoded_token['username']=decodeJWT(token)
    if decoded_token['username'] == current_user:
        return True
    else:
        return True

#current user
async def get_current_user(token: Annotated[str, Depends(auth_pass)]):
    user = User(token)
    '''
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )'''
    return user


