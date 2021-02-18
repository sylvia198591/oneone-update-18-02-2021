from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm,PasswordResetForm
from django.contrib.auth.models import User
from Userdetail.models import *
from django import forms

class RegistrationForm(UserCreationForm):
    accno=forms.IntegerField()
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username", "password1", "password2","accno"]
        wiggets = {
            "first_name": forms.TextInput(attrs={'class': "form-control"}),
            "last_name": forms.TextInput(attrs={'class': "form-control"}),
            "email": forms.EmailInput(attrs={'class': "form-control"}),
            "username": forms.TextInput(attrs={'class': "form-control"}),
            "password1": forms.PasswordInput(attrs={'class': "form-control"}),
            "password2": forms.PasswordInput(attrs={'class': "form-control"}),
            "password2": forms.PasswordInput(attrs={'class': "form-control"}),
            "accno": forms.TextInput(attrs={'class': "form-control"}),
        }

class cuserForm(forms.ModelForm):
    # accno=forms.IntegerField()
    class Meta:
        model=cuser
        fields=["accno"]
        wiggets = {
            "first_name": forms.TextInput(attrs={'class': "form-control"}),}

# class EditUserDetailsForm(forms.ModelForm):
#     class Meta:
#         model = User
#         fields = ["first_name", "last_name", "email", "username"]
#         widgets = {
#             "first_name": forms.TextInput(attrs={'class': "form-control"}),
#             "last_name": forms.TextInput(attrs={'class': "form-control"}),
#             "email": forms.EmailInput(attrs={'class': "form-control"}),
#             "username": forms.TextInput(attrs={'class': "form-control"}),

class EditUserDetailsForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username"]
        widgets = {
            "first_name": forms.TextInput(attrs={'class': "form-control"}),
            "last_name": forms.TextInput(attrs={'class': "form-control"}),
            "email": forms.EmailInput(attrs={'class': "form-control"}),
            "username": forms.TextInput(attrs={'class': "form-control"}),


        }
