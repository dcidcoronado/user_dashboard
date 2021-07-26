from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User, Message, Comment
import bcrypt

def index(request):
    return render(request, 'index.html')    


def signin(request):
    if request.method == 'GET':
        if 'user' in request.session:
            messages.info(request, "You're already logged")
            return redirect('/')
        return render(request, 'signin.html')

    else:
        errors = User.objects.login_validator(request.POST)
        # print(request.POST['email'])
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/signin')

        else:
            user = User.objects.filter(email=request.POST['email'])
            logged_user = user[0]
            userlogged = {
                'id': logged_user.id,
                'first_name': logged_user.first_name,
                'last_name': logged_user.last_name,
                'email': logged_user.email,
                'user_level': logged_user.user_level,
                'description': logged_user.description
                }
            request.session['user'] = userlogged
            if logged_user.user_level == 9:
                request.session['admin'] = userlogged
            elif logged_user.user_level == 5:
                request.session['normal'] = userlogged
            messages.success(request, 'User succesfully logged')
            return redirect('/dashboard')


def register(request):
    if request.method == 'GET':
        if 'user' in request.session:
            messages.info(request, "Logoff to register a new user")
            return redirect('/')
        return render(request, 'register.html')

    else:
        errors = User.objects.basic_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)

            request.session['reg_email'] = request.POST['email']
            request.session['reg_first_name'] = request.POST['first_name']
            request.session['reg_last_name'] = request.POST['last_name']

            return redirect('/register') 

        else:
            if 'reg_email' in request.session:
                del request.session['reg_email']
            if 'reg_first_name' in request.session:
                del request.session['reg_first_name']
            if 'reg_last_name' in request.session:
                del request.session['reg_last_name']

            
            password = request.POST['password']
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            #el primer usuario registrado es admin
            user_level = 5 # 5 para usuario normal 
            if len(User.objects.all()) == 0:
                user_level = 9 # 9 para admin
            User.objects.create(
                email = request.POST['email'],
                first_name = request.POST['first_name'],
                last_name = request.POST['last_name'],
                user_level = user_level,
                password = pw_hash
            )

            messages.success(request, 'User succesfully registered') 

            return redirect('/signin')


def dashboard(request):
    if request.method == 'GET':
        if 'user' not in request.session:
            return redirect('/signin')

        users = User.objects.all()
        context = {
            'users': users
        }
        return render(request, 'dashboard.html', context)


def new_user(request):
    if request.method == 'GET':
        if 'admin' not in request.session:
            messages.warning(request, "You are not an admin")
            return redirect('/dashboard')
        if 'user' not in request.session:
            return redirect('/signin')
        return render(request, 'new.html')

    else:
        errors = User.objects.basic_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)

            request.session['reg_email'] = request.POST['email']
            request.session['reg_first_name'] = request.POST['first_name']
            request.session['reg_last_name'] = request.POST['last_name']

            return redirect('/users/new') 

        else:
            if 'reg_email' in request.session:
                del request.session['reg_email']
            if 'reg_first_name' in request.session:
                del request.session['reg_first_name']
            if 'reg_last_name' in request.session:
                del request.session['reg_last_name']

            
            password = request.POST['password']
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            #el primer usuario registrado es admin
            user_level = 5 # 5 para usuario normal 
            if len(User.objects.all()) == 0:
                user_level = 9 # 9 para admin
            User.objects.create(
                email = request.POST['email'],
                first_name = request.POST['first_name'],
                last_name = request.POST['last_name'],
                user_level = user_level,
                password = pw_hash
            )

            messages.success(request, 'User succesfully created') 

            return redirect('/dashboard')


def show_user(request, user_id):
    if request.method == 'GET':
        if 'user' not in request.session:
            return redirect('/signin')
        user = User.objects.get(id = user_id)
        all_messages = Message.objects.filter(receiver__id = user_id).order_by('-id')
        all_comments = Comment.objects.all().order_by('id')
        context = {
            'user': user,
            'all_messages': all_messages,
            'all_comments': all_comments
        }
        return render(request, 'show.html', context)

    else: 
        errors = Message.objects.basic_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            
            request.session['message'] = request.POST['message']
        
            return redirect(f'/users/show/{user_id}') 

        else:
            if 'message' in request.session:
                del request.session['message']

            this_user = User.objects.get(id = request.session['user']['id'])
            message = request.POST['message']
            receiver = User.objects.get(id = user_id)
            Message.objects.create(
                user = this_user,
                message = message,
                receiver = receiver
            )
            
            messages.success(request, 'Message succesfully posted')

            return redirect(f'/users/show/{user_id}')


def post_comment(request, user_id):
    errors = Comment.objects.basic_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        
        request.session['comment'] = request.POST['comment']
    
        return redirect(f'/users/show/{user_id}')

    else:
        if 'comment' in request.session:
            del request.session['comment']
        
        this_user = User.objects.get(id = request.session['user']['id'])
        message_id = request.POST['message_id']
        this_message = Message.objects.get(id = message_id)
        comment = request.POST['comment']

        Comment.objects.create(
            user = this_user,
            message = this_message,
            comment = comment
        )

        messages.success(request, 'Comment succesfully posted')

        return redirect(f'/users/show/{user_id}')


def edit_user(request):
    if request.method == 'GET':
        if 'user' not in request.session:
            return redirect('/signin')
        return render(request, 'edit.html')
    
    else:
        errors = User.objects.edit_user_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)

            return redirect('/users/edit')

        else:
            this_user = User.objects.get(id = request.session['user']['id'])
            this_user.email = request.POST['email']
            this_user.first_name = request.POST['first_name']
            this_user.last_name = request.POST['last_name']
            this_user.save()

            userlogged = {
                'id': this_user.id,
                'first_name': this_user.first_name,
                'last_name': this_user.last_name,
                'email': this_user.email,
                'user_level': this_user.user_level,
                'description': this_user.description
                }
            request.session['user'] = userlogged

            messages.success(request, 'User information updated')
            
            return redirect('/users/edit')


def edit_description(request):
    errors = User.objects.basic_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)

    else:
        this_user = User.objects.get(id = request.session['user']['id'])
        this_user.description = request.POST['description']
        this_user.save()

        userlogged = {
            'id': this_user.id,
            'first_name': this_user.first_name,
            'last_name': this_user.last_name,
            'email': this_user.email,
            'user_level': this_user.user_level,
            'description': this_user.description
            }
        request.session['user'] = userlogged

        messages.success(request, 'User information updated')

        return redirect('/users/edit')


def edit_password(request):
    errors = User.objects.edit_password_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)

        return redirect('/users/edit')
    
    else:
        this_user = User.objects.get(id = request.session['user']['id'])
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        this_user.password = pw_hash
        this_user.save()

        messages.success(request, 'Password updated')

        return redirect('/users/edit')


def admin_edit(request, user_id):
    if request.method == 'GET':
        if 'admin' not in request.session:
            messages.warning(request, "You are not an admin")
            return redirect('/dashboard')
        if 'user' not in request.session:
            return redirect('/signin')

        user = User.objects.get(id = user_id)

        context = {
            'user': user
        }    
        return render(request, 'admin_edit.html', context)
    
    else:
        errors = User.objects.edit_user_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)

            return redirect(f'/users/edit/{user_id}')

        else:
            this_user = User.objects.get(id = user_id)
            this_user.email = request.POST['email']
            this_user.first_name = request.POST['first_name']
            this_user.last_name = request.POST['last_name']
            this_user.user_level = request.POST['user_level']
            this_user.save()

            userlogged = {
                'id': this_user.id,
                'first_name': this_user.first_name,
                'last_name': this_user.last_name,
                'email': this_user.email,
                'user_level': this_user.user_level,
                'description': this_user.description
                }
            request.session['user'] = userlogged

            messages.success(request, 'User information updated')
            
            return redirect(f'/users/edit/{user_id}')


def admin_edit_password(request, user_id):
    errors = User.objects.edit_password_validator(request.POST)
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)

        return redirect(f'/users/edit/{user_id}')
    
    else:
        this_user = User.objects.get(id = user_id)
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        this_user.password = pw_hash
        this_user.save()

        messages.success(request, 'Password updated')

        return redirect(f'/users/edit/{user_id}')


def remove(request, user_id):
    if request.method == 'GET':
        if 'user' not in request.session:
            return redirect('/signin')
        else:
            if 'admin' not in request.session:
                messages.warning(request, "You are not an admin")
                return redirect('/dashboard')
            else:
                this_user = User.objects.get(id = user_id)
                if this_user.user_level == 5:
                    this_user.delete()
                else:
                    messages.info(request, "You can't remove an admin")
                return redirect('/dashboard')


def logoff(request):
    if 'user' not in request.session:
        return redirect('/signin')
    request.session.flush()
    return redirect('/')