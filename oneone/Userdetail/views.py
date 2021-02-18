from django.shortcuts import render,redirect
from Userdetail.forms import RegistrationForm, EditUserDetailsForm
# from ownerapp.models import Mobile,Brand
from Userdetail.models import *
from django.contrib.auth import login,logout,authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.http import JsonResponse,HttpResponseRedirect,HttpResponseForbidden
from django.shortcuts import *
from django.views.generic import *
# from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import HttpResponse, request
from django.shortcuts import render, redirect
from django.contrib.auth import views as auth_views
# from django.template import loader
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
# from django.conf import settings
# from django.utils.decorators import method_decorator
# from django.views.decorators.cache import never_cache
# from django.views.decorators.csrf import csrf_protect
from django.views.generic.edit import FormView
from django.contrib import messages
import urllib.parse
# from urlparse import urlparse
#from login.html mixin
from urllib.parse import urlparse, urlunparse

from django.conf import settings
# Avoid shadowing the login.html() and logout() views below.
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode,
)
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
# Create your views here.
class createUser(TemplateView):
    form_class=RegistrationForm

    model_name=User

    template_name = "Userdetail/registration.html"
    template_name1 = "Userdetail/registrationo.html"
    def get(self,request,*args,**kwargs):
        context={}
        context["form"]=self.form_class
        # context["form1"] = self.form_class1
        return render(request,self.template_name,context)
    def post(self,request,*args,**kwargs):
        form=self.form_class(request.POST)
        # form1=self.form_class1(request.POST)
        # User = get_user_model()
        if form.is_valid():
            print("aa2")
            # form.save()
            first_name = form.cleaned_data["first_name"]
            last_name = form.cleaned_data["last_name"]
            username = form.cleaned_data["username"]
            email = form.cleaned_data["email"]
            password1 = form.cleaned_data["password1"]
            password2 = form.cleaned_data["password2"]
            accno = form.cleaned_data["accno"]
            # username, first_name, last_name, email, password, accno = kwargs['username'], kwargs['first_name'], kwargs[
            #     'last_name'], kwargs['email'], kwargs['password1'], kwargs['accno']
            qs = User.objects.create_user(username=username, email=email, first_name=first_name, last_name=last_name)

            qs.set_password(password1)
            qs.save()
            rs=User.objects.get(username=username)
            print("rs:",rs.username)
            qs1 = cuser.objects.create(username=qs,accno=accno)
            qs1.save()
            # qs = User.objects.create_user(first_name=first_name, last_name=last_name, email=email, \
            #                          username=username,password1=password1, password2
            #                          =password2, accno=accno)
            # # )
            #
            # def get_success_url(self):
            #
            #     print("qs")
            #     pk = self.kwargs["pk"]
            pk=rs.id
            print(pk)
            context={}
            context["pk"]=pk
            # return redirect("upd", context)

            # qs.save()
            return redirect("login")
            # return render(request, self.template_name1, context)

            # return redirect(reverse('upd', kwargs={'pk': pk}))
        else:
            # return JsonResponse({"message": "loginSuccess", 'status': 200})

            # else:
            return render(request, self.template_name, {"form": form})



    # def get_success_url(self):
    #     return reverse('author-detail', kwargs={'pk': self.object.pk})
# class LoginView(FormView):
#     print("kk")
    # form_class = AuthenticationForm

    # success_url = reverse_lazy('userhome')
    # template_name = 'Userdetail/login.html'

    # def get_success_url(self):
    #     print("cc")
        # return self.get_redirect_url() or self.get_default_redirect_url()

    # def form_valid(self, form):

        # erroneous function which has been fixed
        # do_something(form.cleaned_data['password'])
        # print("HH")
        #
        # return super().form_valid(form)
    # def post(self,request,*args,**kwargs):
    #     print("aa")
        # form=self.form_class(request.POST)
    # def form_valid(self, form_class):
    #     print("aa")
    #     # form=self.form_class(request.POST)
UserModel = get_user_model()
print("um::",UserModel)

class SuccessURLAllowedHostsMixin:
    success_url_allowed_hosts = set()

    def get_success_url_allowed_hosts(self):
        print("aa")
        print(self.request.get_host())
        print(*self.success_url_allowed_hosts)
        return {self.request.get_host(), *self.success_url_allowed_hosts}


class LoginView(SuccessURLAllowedHostsMixin, FormView):
    """
    Display the login.html form and handle the login.html action.
    """
    form_class = AuthenticationForm
    authentication_form = None
    next_page = None
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'Userdetail/login.html'
    redirect_authenticated_user = False
    extra_context = None

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        print("bb")
        print("rau:::",self.redirect_authenticated_user)
        print("raut:::", self.request.user.is_authenticated)
        if self.redirect_authenticated_user and self.request.user.is_authenticated:
            redirect_to = self.get_success_url()
            print("rt:::",redirect_to)
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "
                    "your LOGIN_REDIRECT_URL doesn't point to a login.html page."
                )
            return HttpResponseRedirect(redirect_to)
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        print("cc")
        print('cc:::',self.get_redirect_url())
        print('cd:::', self.get_default_redirect_url())
        return self.get_redirect_url() or self.get_default_redirect_url()

    def get_redirect_url(self):
        print("dd")
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        print("rrrtt::::",redirect_to)
        url_is_safe = url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ''

    def get_default_redirect_url(self):
        print("ee")
        """Return the default redirect URL."""
        return resolve_url(self.next_page or settings.LOGIN_REDIRECT_URL)

    def get_form_class(self):
        print("ff")
        return self.authentication_form or self.form_class

    def get_form_kwargs(self):
        print("gg")
        kwargs = super().get_form_kwargs()
        kwargs['request'] = self.request
        print("kw::",kwargs)
        return kwargs

    def form_valid(self, form):
        print("hh")
        """Security check complete. Log the user in."""
        auth_login(self.request, form.get_user())
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        print("ii")
        context = super().get_context_data(**kwargs)
        current_site = get_current_site(self.request)
        print("CCC!!!::",context)
        context.update({
            self.redirect_field_name: self.get_redirect_url(),
            'site': current_site,
            'site_name': current_site.name,
            **(self.extra_context or {})
        })
        print("cccc:::",context)
        return context



# class LoginView(FormView):
#     """
#     Display the login.html form and handle the login.html action.
#     """
#     form_class = AuthenticationForm
#     authentication_form = None
#     # next_page = None
#     # redirect_field_name = REDIRECT_FIELD_NAME
#     template_name = 'Userdetail/login.html'
#     # redirect_authenticated_user = False
#     # extra_context = None
#     success_url = reverse_lazy('userhome')
#     # def get_initial(self):
#     #     initial = super(LoginView, self).get_initial()
#     #     print("I::::",initial)
#     #     if self.request.user.is_authenticated:
#     #         initial.update({'name': self.request.user.get_full_name()})
#     #         print("init:::",initial)
#     #     return initial
#     def get_form_kwargs(self):
#         print("gg")
#         kwargs = super().get_form_kwargs()
#         kwargs['request'] = self.request
#         print("kw::",kwargs)
#         return kwargs
#     def form_valid(self, form):
#         print("hh")
#         print("sdfds::",form.get_user())
#         # username = form.cleaned_data["username"]
#         # email = form.cleaned_data["email"]
#         # password = form.cleaned_data["password"]
#         uname=request.POST.get('uname')
#         pwd=request.POST.get('pwd')
#         user = authenticate(request, username=uname, password=pwd)
#         # user=form.get_user()
#         """Security check compl ete. Log the user in."""
#         # user=form.get_user()
#         auth_login(request, self.get_form_kwargs())
#         # auth_login(request, user)
#         au=self.request.user.is_authenticated
#         print("au::",au)
#         if self.request.user.is_authenticated:
#         # if form.get_user() is not None:
#             print("dd")
#             # request.user=form.get_user()
#             auth_login(request,form.get_user())
#             return HttpResponseRedirect(self.get_success_url())
#             # print("Aa")
#             # return redirect("userhome")
#         # auth_login(request, form.get_user())
#     #     return render(request,self.get_success_url)
#     #
#     # def get_success_url(self):
#     #     print("cc")
#     #     # print('cc:::',self.get_redirect_url())
#     #     # print('cd:::', self.get_default_redirect_url())
#     #     return redirect("userhome")

class Signin(auth_views.LoginView):
    template_name = 'Userdetail/login.html'

class userUpdate(UpdateView):
    model = User
    fields=['email']
    success_url = reverse_lazy('userhome')
    template_name="Userdetail/login.html"
# class LoginView(FormView):
#     form_class = AuthenticationForm
#
#     success_url = reverse_lazy('userhome')
#     template_name = 'Userdetail/login1.html'
def userHome(request):
    print(request.user)
    return render(request, "Userdetail/userhome.html", context={'user': request.user})
    # return render(request, "Userdetail/userhome.html")
    # def get(self,request,*args,**kwargs):
    #     context={}
    #     context["form"]=self.form
    #     # context["form1"] = self.form_class1
    #     return render(request,self.template_name,context)
    #
    # def post(self, request, *args, **kwargs):
    #     print('aa')
    #     # form = self.get_form_class()
    #     form = self.form(request.POST)
    #     # Verify form is valid
    #     if form.is_valid():
    #         print("AA")
    #         # Call parent form_valid to create model record object
    #         super(LoginView, self).form_valid(form)
    #         # Add custom success message
    #         messages.success(request, 'Item created successfully!')
    #         # Redirect to success page
    #         return HttpResponseRedirect(self.get_success_url())
    #     else:
    #         print("bg")
    #     # Form is invalid
    #     # Set object to None, since class-based view expects model record object
    #     # self.object = None
    #     # Return class-based view form_invalid to generate form with errors
    #     return render(request, self.template_name, {"form": form})

    # def form_valid(self, form_class):
    #     super(LoginView, self).form_valid(form_class)
    #     # Add action to valid form phase
    #     messages.success(self.request, 'Item created successfully!')
    #     return HttpResponseRedirect(self.get_success_url())
    #
    # def form_invalid(self, form_class):
    #     # Add action to invalid form phase
    #     return self.render_to_response(self.get_context_data(form=form_class))
# def userRegistration(request):
#     form=RegistrationForm()
#     print("aa")
#     context={}
#     context["form"]=form
#     if request.method=='POST':
#         print("aa1")
#         form=RegistrationForm(request.POST)
#         print("aa3")
#         if form.is_valid():
#             print("aa2")
#             # form.save()
#             first_name = form.cleaned_data["first_name"]
#             last_name = form.cleaned_data["last_name"]
#             email = form.cleaned_data["email"]
#             password1 = form.cleaned_data["password1"]
#             password2 = form.cleaned_data["password2"]
#             accno = form.cleaned_data["accno"]
#             qs = User.objects.create(first_name=first_name, last_name=last_name, email=email, \
#                                       password1=password1, password2
#                                       =password2, accno=accno)
#                                         # )
#
#             qs.save()
#             return redirect("login.html")
#         else:
#             context["form"]=form
#             return render(request, "Userdetail/registration.html", context)
#
#     return render(request,"Userdetail/registration.html",context)

# Create your views here.

# def userRegistration(request):
#     form=RegistrationForm()
#     print("aa")
#     context={}
#     context["form"]=form
#     if request.method=='POST':
#         print("aa1")
#         form=RegistrationForm(request.POST)
#         print("aa3")
#         if form.is_valid():
#             print("aa2")
#
#             form.save()
#             cuser.save()
#             return redirect("login.html")
#         else:
#             context["form"]=form
#             return render(request, "Userdetail/registration.html", context)
#
#     return render(request,"Userdetail/registration.html",context)



@login_required(login_url='login.html')
def userLogout(request):
    logout(request)
    return redirect("login.html")

def editUserDetails(request):
    user=User.objects.get(username=request.user)
    form=EditUserDetailsForm(instance=user)
    context={}
    context["form"]=form
    if request.method=='POST':
        form=EditUserDetailsForm(instance=user,data=request.POST)
        if form.is_valid():
            form.save()
            return redirect("userhome")
        else:
            context["form"]=form
            return render(request,"Userdetail/editprofile.html",context)
    return render(request, "Userdetail/editprofile.html", context)



