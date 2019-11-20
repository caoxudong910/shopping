# Create your views here.
import hashlib
import random
import base64
import json

from urllib.parse import unquote
from celery_tasks.user_tasks import send_verify
from .models import UserProfile, Address, WeiboUser
from django_redis import get_redis_connection
from django.views.generic import View
from django.http import JsonResponse
from django.db import transaction
from dtoken.views import make_token
from .weiboapi import OAuthWeibo
# from utils.loging_decorator import logging_check,get_username_by_request,get_user_by_request

# Create your views here.

class CreateAddresses(View):
    """
    用来生成用户地址列表
    """
    def get_address_list(self,alladdress):
        pass


class ModifyPasswordView(View):
    """
    用户登陆状态下 修改密码：
    http://127.0.0.1:8000/v1/user/<username>/password
    """

    @logging_check
    def post(self, request, username):
        """
        :param request:
        :return:
        """
        user = get_user_by_request(request)
        data = json.loads(request.body)
        oldpassword = data.get('oldpassword', None)
        password1 = data.get('password1', None)
        password2 = data.get('password2', None)
        if not oldpassword:
            return JsonResponse({'code': 10103, 'error': {'message': 'Old password error!'}})
        if not password1:
            return JsonResponse({'code': 10108, 'error': {'message': 'please enter your password!'}})
        if not password2:
            return JsonResponse({'code': 10109, 'error': {'message': 'Confirm that the password is incorrect!'}})
        if oldpassword == password1 or oldpassword == password2:
            return JsonResponse({'code': 10109, 'error': {'message': 'Use Different Password!'}})
        token_username = get_username_by_request(request)
        if token_username != username:
            return JsonResponse({'code': 10131, 'error': {'message': 'User not logged in!'}})
        # 判断两次密码是否一致
        if password1 != password2:
            return JsonResponse({'code': 10102, 'error': {'message': 'Inconsistent passwords!'}})
        try:
            user = UserProfile.objects.get(username=token_username)
        except Exception as e:
            return JsonResponse({'code': 10104, 'error': {'message': 'User query error'}})
        real_password = user.password
        m = hashlib.md5()
        m.update(oldpassword.encode())
        if m.hexdigest() != real_password:
            return JsonResponse({'code': 10103, 'error': {'message': 'Old password error!'}})
        new = hashlib.md5()
        new.update(password1.encode())
        user.password = new.hexdigest()
        user.save()
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})

class SendSmsCodeView(View):
    """
    用户找回密码视图处理函数：
    分为三步：
    1.验证邮箱，并且发送邮件验证码
    2.验证邮件验证码，
    3.验证码验证成功，修改密码
    """

    def post(self, request):
        pass

class VerifyCodeView(View):
    """
    第二步 验证发送邮箱的验证码
    """

    def post(self, request, username):
       pass


class ModifyPwdView(View):
    """
    最后一步验证邮箱，修改密码
    """

    def post(self, request, username):
        pass


class ActiveView(View):
    """
    # 用户发送邮件激活
    # GET http://127.0.0.1:8000/v1/user/active?code=xxxxx&username=xxx
    """
    def get(self, request):
       pass

class AddressView(CreateAddresses):
    """
    get: 获取用户的绑定的收获地址
    post: 新增用户绑定的收获地址
    delete：实现用户删除地址功能
    put: 实现用户修改地址功能
    """
    @logging_check
    def get(self, request, username, id=None):
        """
        返回用户关联的地址页面，以及地址
        :param request:
        :return: addressAdmin.html & addresslist
        """
        pass

    @logging_check
    def post(self, request, username, id=None):
        """
        用来提交保存用户的收获地址
        1.先获取相应的用户，然后根据用户的id来绑定地址
        :param request:
        :return:返回保存后的地址以及地址的id
        """
        pass
              

    @logging_check
    def delete(self, request, username, id=None):
        """
         删除用户的提交的地址
         :param request: 提交的body中为用户的地址的id
         :param username:
         :return: 删除后用户的所有的收获地址
        """
        # 根据用户发来的地址的id来直接删除用户地址
        pass

    @logging_check
    def put(self, request, username, id=None):
        pass


class DefaultAddressView(CreateAddresses):
    """
    用来修改默认地址
    """
    @logging_check
    def post(self, request, username):
        """
        用来修改默认地址
        :param request:用户请求对象
        :param address_id:用户修改地址的id
        :return:
        """
        # 先根据address_id 来匹配出用户的id
        # 找到用户的id之后选出所有的用户地址。
        # 在将用户地址id为address_id 设为默认
       pass

class OAuthWeiboUrlView(View):
    def get(self, request):
        """
        用来获取微博第三方登陆的url
        :param request:
        :param username:
        :return:
        """
        pass 

class OAuthWeiboView(View):
    def get(self, request):
        """
        获取用户的code,以及用户的token
        :param request:
        :return:
        """
        # 首先获取两个参数code 和state
        pass

    def post(self, request):
        """
        此时用户提交了关于个人信息以及uid
        创建用户，并且创建绑定微博关系
        :param requset:
        :return:
        """
        pass 


class Users(View):
    def get(self, request, username=None):
        pass

    def post(self, request):

        json_str = request.body
        if not json_str:
            result = {'code': 10132, 'error': 'No data found'}
            return JsonResponse(result)

        json_obj = json.loads(json_str)

        username = json_obj.get('uname')
        if not username:
            result = {'code': 202, 'error': 'Please give me username'}
            return JsonResponse(result)
        email = json_obj.get('email')
        if not email:
            result = {'code': 203, 'error': 'Please give me email'}
            return JsonResponse(result)
        # 优先查询当前用户名是否已存在
        old_user = UserProfile.objects.filter(username=username)

        if old_user:
            result = {'code': 206, 'error': 'Your username is already existed'}
            return JsonResponse(result)

        password = json_obj.get('password')
        m = hashlib.md5()
        m.update(password.encode())

        phone = json_obj.get('phone')
        if not phone:
            result = {'code': 207, 'error': 'Please give me phone'}
            return JsonResponse(result)

        try:
            UserProfile.objects.create(username=username, password=m.hexdigest(),
                                       email=email, phone=phone)
        except Exception as e:
            result = {'code': 208, 'error': 'Server is busy'}
            return JsonResponse(result)
        # 发送用户激活链接
        code_str = username + '.' + email
        # 生成激活链接：
        active_code = base64.b64encode(code_str.encode(encoding='utf-8')).decode('utf-8')
        redis_conn = get_redis_connection('verify_email')
        ### todo : 用户激活链接永久有效
        redis_conn.set("email_active_%s" % email, active_code)
        verify_url = 'http://114.116.244.115:7000/dadashop/templates/active.html?code=%s&username=%s' % (active_code, username)
        token = make_token(username)
        result = {'code': 200, 'username': username, 'data': {'token': token.decode()}}
        send_verify.delay(email=email, verify_url=verify_url, sendtype=1)
        return JsonResponse(result)


class SmScodeView(View):
    """
    实现短信验证码功能
    """
    def post(self, request):
        """
        短信测试：
        :param request:
        :return:
        """
        data = json.loads(request.body)
        if not data:
            return JsonResponse({'code': 10131, 'error': {'message': 'Invalid phone number!'}})
        phone = data.get('phone', None)
        code = "%06d" % random.randint(0, 999999)
        try:
            redis_conn = get_redis_connection('verify_email')
            redis_conn.setex("sms_code_%s" % phone, 3 * 60, code)
        except Exception as e:
            return JsonResponse({'code': 10105, 'error': {'message': 'Storage authentication code failed'}})
        send_verify.delay(phone=phone, code=code, sendtype=2)
        return JsonResponse({'code': 200, 'data': {'message': 'OK'}})
