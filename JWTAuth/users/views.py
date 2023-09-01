
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.conf import settings
from django.shortcuts import render
from django.contrib.auth import get_user_model
# Create your views here.
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework import generics, permissions
from knox.models import AuthToken
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import NewUserSerializer   
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated,AllowAny
from datetime import datetime
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
# Create your views here.
from knox.views import LoginView as KnoxLoginView
from knox.views import LogoutView
from rest_framework.fields import empty
from rest_framework.views import APIView
from rest_framework import status
from .models import *
from details.models import Employee
from rest_framework import generics
from .serializers import *
from rest_framework.response import Response
from django.contrib.auth import SESSION_KEY, authenticate, login
from datetime import date, datetime
from datetime import datetime,timezone
from rest_framework import permissions
import string
import random
from rest_framework_simplejwt.tokens import RefreshToken
# from .models import RefreshTokens



class CreateNewUser(generics.CreateAPIView):
    # permission_classes = [IsAuthenticated]
    # serializer_class = NewUserSerializer

    def post(self, request, format=None):
        result = {}
        result['status'] = 'NOK'
        result['valid'] = False
        result["result"] = {'message': 'Unauthorized', 'data': []}
        if True:

            serializer = NewUserSerializer(data=request.data)
            if serializer.is_valid():

                try:
                    username = serializer.validated_data['email']
                    password = serializer.validated_data['password']

                    serializer.save()
                    name = request.data['name']
                    email = request.data['email']
                except:
                    result['status'] = 'NOK'
                    result['valid'] = False
                    # result['result']['message'] = "Error in sending mail"
                    return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

                result['status'] = 'OK'
                result['valid'] = True
                result['result']['message'] = "User created successfully !"
                return Response(result, status=status.HTTP_200_OK)
            else:
                result['result']['message'] = (list(serializer.errors.keys())[
                                                   0] + ' - ' + list(serializer.errors.values())[0][0]).capitalize()
                return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)



# #######    LOGIN using JWT Athentication
class Login(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        result = {}
        result['status'] = 'NOK'
        result['valid'] = False
        result['result'] = {"message": "Unauthorized access", "data": []}
        if serializer.is_valid():
            try:
                
                # user_data = authenticate(request=request, username=serializer.validated_data['email'], password=serializer.validated_data['password'])

                user_data = authenticate(email=serializer.validated_data['email'],
                                         password=serializer.validated_data['password'])
            except:
                # Response data
                result['status'] = 'NOK'
                result['valid'] = False
                result['result']['message'] = 'User not present'
                # Response data
                return Response(result, status=status.HTTP_204_NO_CONTENT)

            if user_data is not None:
                user_details = CustomUser.objects.all().filter(email=user_data).values('id')
                                                                                
                if user_data.is_active:
                    refresh = RefreshToken.for_user(user_data)
                    token={}
                    token = {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                   
                    # data['user_info'] = user_details

                # Response data
                result['status'] = "OK"
                result['valid'] = True
                result['result']['message'] = "Login successfully"
                result['result']['data'] = token
                # result['result']['data'] = data
                # Response data
                user_data.is_login=True
                user_data.save()
                return Response(result, status=status.HTTP_200_OK)
            else:

                # Response data
                result['status'] = "NOK"
                result['valid'] = False
                result['result']['message'] = 'Invalid Credentials'
                # Response data
                return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        # Response data
        result['status'] = "NOK"
        result['valid'] = False
        result['result']['message'] = (
                    list(serializer.errors.keys())[0] + ' - ' + list(serializer.errors.values())[0][0]).capitalize()
        # Response data
        return Response(result, status=status.HTTP_422_UNPROCESSABLE_ENTITY)




class UserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = AllUsersSerializer

####### LOGOUT JWT Authenticstion

class Logout(APIView):
    
    def post(self, request, *args, **kwargs):
        permission_classes = [permissions.IsAuthenticated,]
        serializer = LogoutSerializer(data=request.data)
        user = request.user
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            if user.is_login:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()  # Blacklist the refresh token
                    user.is_login = False
                    user.save()
                    result = {
                        'status': 'OK',
                        'message': 'Logout successful'
                    }
                    return Response(result, status=status.HTTP_200_OK)
                except TokenError:
                    result = {
                        'status': 'NOK',
                        'message': 'Error while logging out'
                    }
                    return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                result = {
                        'status': 'OK',
                        'message': 'Already logged out'
                    }
                return Response(result, status=status.HTTP_204_NO_CONTENT)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class LogoutAllUsersView(APIView):
    permission_classes = [permissions.IsAuthenticated,]
    
    def post(self, request):
        # a = RefreshTokens.objects.all()
        # print("fjfjf",a)
        serializer = LogoutAllSerializer(data=request.data)
        
        if serializer.is_valid():
            admin_user = request.user
            
            if admin_user.is_staff and admin_user.id==1:             
                active_users = get_user_model().objects.filter(is_login=True)
                for user in active_users:
                    refresh_tokens = RefreshToken.for_user(user)
                    refresh_tokens.blacklist()
                    user.is_login = False
                    user.save()
                
                    return Response({'message': 'All users have been logged out successfully'}, status=status.HTTP_200_OK)
                if not active_users:
                    return Response({'message': 'All users have already been logged out successfully '}, status=status.HTTP_204_NO_CONTENT)
            
            return Response({'message': 'Not a superuser'}, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    


