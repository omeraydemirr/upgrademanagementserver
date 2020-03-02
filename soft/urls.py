"""soft URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from firmware.views import *
from django.urls import include, path
from django.views.decorators.csrf import *
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls import url , include
from rest_framework.urlpatterns import format_suffix_patterns
from firmware import views
from django.views.decorators.csrf import *
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    url(r'^loginpage',csrf_exempt(views.loginpage),name='loginpage'),
    url(r'^loginfirst', csrf_exempt(views.loginfirst), name='loginfirst'),
    url(r'^forgotpassw', csrf_exempt(views.forgot_request), name='forgot_passw'),
    url(r'^resetpassw', csrf_exempt(views.confirmation_request), name='reset_passw'),
    url(r'^logout', csrf_exempt(views.logout), name='logout'),
    url (r'^$', csrf_exempt(home_view),name='home'),


    path('upgrade/', csrf_exempt(send_json), name='send_json'),
    url(r'^firmware', csrf_exempt(views.return_file)),
    url(r'^status', csrf_exempt(views.statusJson), name='status'),

    url(r'^cloud/upload/', csrf_exempt(upload_file), name='upload'),
    url(r'^cloud/upload-default/', csrf_exempt(upload_default_file), name='upload_default'),
    url(r'^deletefirmware', csrf_exempt(views.delete_firmware), name='delete'),
    url(r'^loglist', csrf_exempt(views.loglist),name='loglist'),
    url(r'^macadress',csrf_exempt(views.fform),name='macadress'),
    url(r'^addplatform',csrf_exempt(views.addplatform),name='platformadd'),
    url (r'^platformdelete', csrf_exempt (views.delete_platform), name = 'delete_pmac'),

]
#urlpatterns = format_suffix_patterns(urlpatterns)
urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.DOWNLOAD_URL,document_root=settings.DOWNLOAD_ROOT)
urlpatterns += [
    path('test1/', csrf_exempt(views.macPanel)),
    path('test2/', csrf_exempt(views.macPanelInfo), name = 'get_mac_info'),
    path('test4/', csrf_exempt(views.firmwarePanelInfo), name='get_firmware_info'),
    path('test5/', csrf_exempt(views.groupPanelInfo), name='get_group_info'),
    path('test6/', csrf_exempt(views.firmPanel), name='firm_info'),
    path('test7/', csrf_exempt(views.firmwarePanelInfo), name='get_firmware_info1'),
    path('test8/', csrf_exempt(views.groupPanelInfo), name='get_group_info1'),

]
