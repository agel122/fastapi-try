import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt

from tortoise.contrib.fastapi import register_tortoise

from models import User, User_Pydantic, UserIn_Pydantic, Record, Record_Pydantic, RecordIn_Pydantic


app = FastAPI()

JWT_SECRET = 'myjwtsecret'


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    token = jwt.encode(user_obj.dict(), JWT_SECRET)
    return {'access_token': token, 'token_type': 'bearer'}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )
    return await User_Pydantic.from_tortoise_orm(user)


@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


@app.post('/records', response_model=Record_Pydantic)
async def create_record(record: RecordIn_Pydantic, user: User_Pydantic = Depends(get_current_user)):
    record_data = record.dict()
    record_data.update({"author_id": user.id})
    obj = await Record.create(**record_data)
    return await Record_Pydantic.from_tortoise_orm(obj)


@app.get('/records/my', response_model=list[Record_Pydantic])
async def get_records(user: User_Pydantic = Depends(get_current_user)):
    return await Record_Pydantic.from_queryset(Record.filter(author__id=user.id))


@app.get('/records/my/{record_id}', response_model=Record_Pydantic)
async def get_record(record_id: int, user: User_Pydantic = Depends(get_current_user)):
    record = await Record.get(id=record_id)
    if user.id != record.author_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="it's not your data"
        )
    return await Record_Pydantic.from_queryset_single(Record.get(id=record_id))


@app.delete('/records/my/{record_id}')
async def get_record(record_id: int, user: User_Pydantic = Depends(get_current_user)):
    record = await Record.get(id=record_id)
    if user.id != record.author_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="it's not your data, you can't delete it"
        )
    await record.delete()
    return {'deleted message': record_id}


@app.put('/records/my/{record_id}', response_model=Record_Pydantic)
async def update_record(record_id: int, new_record: RecordIn_Pydantic,
                        user: User_Pydantic = Depends(get_current_user)):
    record = await Record.get(id=record_id)
    if user.id != record.author_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="it's not your data, you can't update it"
        )
    new_record_data = new_record.dict()
    new_record_data.update({"author_id": user.id})
    await Record.filter(id=record_id).update(**new_record_data)
    return await Record_Pydantic.from_queryset_single(Record.get(id=record_id))


register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)
