from tortoise import fields
from tortoise.models import Model
from tortoise.contrib.pydantic import pydantic_model_creator

from passlib.hash import bcrypt


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


class Record(Model):
    id = fields.IntField(pk=True)
    record = fields.CharField(max_length=500)
    author: fields.ForeignKeyRelation[User] = fields.ForeignKeyField('models.User', related_name='authors')


User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

Record_Pydantic = pydantic_model_creator(Record, name='Record')
RecordIn_Pydantic = pydantic_model_creator(Record, name='RecordIn', exclude_readonly=True, exclude=('author_id',))
