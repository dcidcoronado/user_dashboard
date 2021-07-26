from django.db import models
import re
from datetime import datetime
import bcrypt
import datetime

# Create your models here.
class UserManager(models.Manager):
    def basic_validator(self, postData):
        errors = {}

        NAME_REGEX = re.compile(r'^[A-ZÀ-ÿ\u00d1][a-zÀ-ÿ\u00f1\u00d1]+$')
        EMAIL_REGEX = re.compile(r'[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+$')

        if len(postData['first_name']) == 0:
            errors['first_name'] = "Must enter a first name"
        else:
            if not NAME_REGEX.match(postData['first_name']):
                errors['first_name'] = "First Name must start with a capital letter"

        if len(postData['last_name']) == 0:
            errors['last_name'] = "Must enter a last name"
        else:
            if not NAME_REGEX.match(postData['last_name']):
                errors['last_name'] = "Last name must start with a capital letter"

        if len(postData['email']) == 0:
            errors['email'] = "Must enter an email"
        else:
            if not EMAIL_REGEX.match(postData['email']):
                errors['email'] = "Must enter a valid email"
            elif User.objects.filter(email=postData['email']):
                errors['email'] = "Must be a new User"
    
        if len(postData['password']) == 0:
            errors['password'] = "Must enter a password"
        else:
            if postData['password'] != postData['cpassword']:
                errors['password'] = "Passwords doesn't match"
            elif len(postData['password']) < 8:
                errors['password'] = "Password must be at least 8 characters long"

        return errors


    def edit_user_validator(self, postData):
        errors = {}

        NAME_REGEX = re.compile(r'^[A-ZÀ-ÿ\u00d1][a-zÀ-ÿ\u00f1\u00d1]+$')
        EMAIL_REGEX = re.compile(r'[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+$')

        if len(postData['first_name']) == 0:
            errors['first_name'] = "Must enter a first name"
        else:
            if not NAME_REGEX.match(postData['first_name']):
                errors['first_name'] = "First Name must start with a capital letter"

        if len(postData['last_name']) == 0:
            errors['last_name'] = "Must enter a last name"
        else:
            if not NAME_REGEX.match(postData['last_name']):
                errors['last_name'] = "Last name must start with a capital letter"

        if len(postData['email']) == 0:
            errors['email'] = "Must enter an email"
        else:
            if not EMAIL_REGEX.match(postData['email']):
                errors['email'] = "Must enter a valid email"

        return errors


    def edit_password_validator(self, postData):
        errors = {}
        if len(postData['password']) == 0:
            errors['password'] = "Must enter a password"
        else:
            if postData['password'] != postData['cpassword']:
                errors['password'] = "Passwords doesn't match"
            elif len(postData['password']) < 8:
                errors['password'] = "Password must be at least 8 characters long"

        return errors


    def login_validator(self, postData):
        user = User.objects.filter(email=postData['email'])
        errors = {}
        # print(user)
        if len(user) > 0:
            if bcrypt.checkpw(postData['password'].encode(), user[0].password.encode()) is False:
                errors['user'] = "Invalid user"
        else:
            errors['user'] = "Invalid user"
        return errors 


class MessageManager(models.Manager):
    def basic_validator(self, postData):
        errors = {}

        if len(postData['message']) == 0:
            errors['message'] = 'Please, leave a message'
        
        return errors


class CommentManager(models.Manager):
    def basic_validator(self, postData):
        errors = {}

        if len(postData['comment']) == 0:
            errors['comment'] = 'Please, leave a comment'

        return errors


class User(models.Model):
    email = models.CharField(max_length=50)
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length=40)
    user_level = models.IntegerField(default=0)
    password = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True)

    objects = UserManager()


class Message(models.Model):
    user = models.ForeignKey(User, related_name="messages", on_delete = models.CASCADE)
    message = models.TextField()
    receiver = models.ForeignKey(User, related_name="message_receiver", on_delete = models.CASCADE, null = True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = MessageManager()


class Comment(models.Model):
    message = models.ForeignKey(Message, related_name="comments", on_delete = models.CASCADE)
    user = models.ForeignKey(User, related_name="comments", on_delete = models.CASCADE)
    comment = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CommentManager()