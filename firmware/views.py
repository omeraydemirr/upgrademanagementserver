import time
from http import server
import request
from boto3 import session
from django.contrib.sites import requests
from django_fields import *
from django.http import JsonResponse
import shutil
import zipfile
from django.core.files.storage import default_storage, FileSystemStorage
import json
from firmware.forms import *
import boto3
from boto3.dynamodb.conditions import Key, Attr
from django.shortcuts import render, HttpResponse, HttpResponseRedirect, get_object_or_404, redirect, \
    render_to_response, HttpResponsePermanentRedirect, Http404
from OpenSSL import crypto
from django.core.files import File
from django.core.files.base import ContentFile
import base64
import OpenSSL
import Crypto
from django.utils.crypto import get_random_string
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from django.core.files.storage import default_storage, FileSystemStorage
from django.utils.datastructures import MultiValueDictKeyError
import pkgutil
import datetime
from _datetime import datetime
import os
from os import path
import numpy
import numpy as np
import urllib3
from django.contrib.sessions.backends.file import *
from django.http import HttpResponse
from django.shortcuts import render
import requests
from django.contrib.sessions import*
from django.contrib.sessions.backends.signed_cookies import *
import subprocess
import tarfile
import gzip
import re
from django.contrib import messages
from django.urls import resolve
from django.core import serializers



"""
    Below set is used to hold
    mac adresses of the firmware download
    requester blaumds.
    Mutex is used to avoid synchronization issues.
"""
from threading import Lock, Condition
firmwareDownloadedMacs = set()
firmwareDMMutex = Lock()
firmwareDMCv = Condition(firmwareDMMutex)


#Defining Table Name According to Current URL of Server that blaums exists.
def defineTableName(request):
    client = boto3.resource(
        'dynamodb',
        aws_access_key_id='',
        aws_secret_access_key='',
        region_name='',
    )
    try:
        serverurl = request.META['HTTP_HOST']
        if str(serverurl) == 'blaums.bla-bla.com' or str(serverurl) == 'bla-c.eu-central-1.elasticbeanstalk.com':
            table = client.Table('Firmware')
        else:
            table = client.Table('FirmwareV2')
        return table
    except:
        return False

#DynamoDB QUERIES:
def getSituationRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Situation',
            FilterExpression=Key("MacAddr").eq(mac),
        )

    except:
        return None
    response = response["Items"]
    return response

def getSituationRespectoFirmware(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Situation',
            FilterExpression=Key("Firmware").eq(firmware),
        )

    except:
        return None
    response = response["Items"]
    return response

def getLogLevelRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='StartLog',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response


def getLogLevelRespectoFirmware(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='StartLog',
            FilterExpression=Key("Firmware").eq(firmware),
        )
    except:
        return None

    response = response["Items"]
    return response



def getGroupRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='GroupID',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response

def getMd5RespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='md5sum',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response



def getGroupRespectoFirm(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='GroupID',
            FilterExpression=Key("Firmware").eq(firmware),
        )
    except:
        return None

    response = response["Items"]
    return response



def getPlatformRespectMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='PlatformType',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response

def getPlatformRespectFirm(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='PlatformType',
            FilterExpression=Key("Firmware").eq(firmware),
        )
    except:
        return None

    response = response["Items"]
    return response



def getStatusTimeRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='StatusTime',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response

def getStatusTimeRespectoFirmware(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='StatusTime',
            FilterExpression=Key("Firmware").eq(firmware),
        )
    except:
        return None

    response = response["Items"]
    return response

def getArchivedRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Archived',
            FilterExpression=Key("MacAddr").eq(mac),
        )

    except:
        return None
    response = response["Items"]
    return response

def getArchivedRespectoFirmware(request,firmware):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Archived',
            FilterExpression=Key("Firmware").eq(firmware),
        )

    except:
        return None
    response = response["Items"]
    return response

def groupId(request,platformType):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression="GroupID",
            FilterExpression=Key("PlatformType").eq(platformType),
        )
    except:
        return None

    return response['Items']


def getMacAddr(request,platformType):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression="MacAddr",
            FilterExpression=Key("PlatformType").eq(platformType),
        )
    except:
        return None

    return response['Items']


def getMacAddress(request,groupNumbers):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression="MacAddr",
            FilterExpression=Key("GroupID").eq(groupNumbers),
        )
    except:
        return None

    return response['Items']


def getMacAddresses(request,firmware):
    try:
        table = defineTableName(request)
        response = table.scan(
            ProjectionExpression="MacAddr",
            FilterExpression=Key("Firmware").eq(firmware),
        )
    except:
        return None

    return response['Items']


def getPlatormTypes(request,unique=False):

    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='PlatformType'
        )
    except:
        return None

    response = response["Items"]
    if unique:
        response = list({v['PlatformType']: v for v in response}.values())
        return response
    else:
        return response

def getFirmwares(request,unique=False):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Firmware'
        )
    except:
        return None

    response = response["Items"]
    if unique:
        response = list({v['Firmware']: v for v in response}.values())
        return response
    else:
        return response


def getGroupIdRespectPlatform(request,platformType,unique=False):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='GroupID',
            FilterExpression=Key("PlatformType").eq(platformType),
        )
    except:
        return None

    response = response["Items"]
    if unique:
        response = list({v['GroupID']: v for v in response}.values())
        return response
    else:
        return response


def getFirmwaresRespectPlatform(request,platformType, unique=False):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Firmware',
            FilterExpression=Key("PlatformType").eq(platformType),
        )
    except:
        return None

    response = response["Items"]
    if unique:
        response = list({v['Firmware']: v for v in response}.values())
        return response
    else:
        return response


def getFirmwaresRespectoMac(request,mac):
    try:
        table = defineTableName(request)

        response = table.scan(
            ProjectionExpression='Firmware',
            FilterExpression=Key("MacAddr").eq(mac),
        )
    except:
        return None

    response = response["Items"]
    return response

def deletePlatform(platformType,request):
    table = defineTableName(request)
    try:
        scanResponse = table.scan(
            ProjectionExpression="MacAddr,Firmware,PlatformType",
            FilterExpression=Key("PlatformType").eq(platformType)
        )
    except:
        return False

    items = scanResponse["Items"]
    for item in items:
        try:
            firmware = item["Firmware"]
            mac = item["MacAddr"]

            table.delete_item(
                Key={
                    'MacAddr': mac,
                    'Firmware': firmware,
                },
            )
        except:
            return False

    return True


def deleteMacAddress(request,platformType, macAddr):
    table = defineTableName(request)
    try:
        scanResponse = table.scan(
            ProjectionExpression="MacAddr,Firmware,PlatformType",
            FilterExpression=Key("PlatformType").eq(platformType) & Key("MacAddr").eq(macAddr),
        )
    except:
        return False

    items = scanResponse["Items"]
    for item in items:
        try:
            firmware = item["Firmware"]
            mac = item["MacAddr"]

            table.delete_item(
                Key={
                    'MacAddr': mac,
                    'Firmware': firmware,
                },
            )
        except:
            return False

    return True


# delete a firmware with respect to given platform type and firmware name
# from database also remove the firmware from storage
def deleteFirmwareRespecttoPlatform(request,platformType, firmwareName):
    table = defineTableName(request)
    scanResponse = table.scan(
        ProjectionExpression="MacAddr,Firmware,PlatformType",
        FilterExpression=Key("PlatformType").eq(platformType) & Key("Firmware").eq(firmwareName),
    )

    success = True
    items = scanResponse["Items"]
    for item in items:
        mac = item["MacAddr"]
        firmware = item["Firmware"]
        platform = item["PlatformType"]
        groupId = item["GroupID"]

        if not deleteFileFromDb(request,table, mac, firmware, platform,groupId):
            success = False
            break

    if success:
        # since firmware removed for platform,it is also removed from storage
        pathToFirmware = "bin/" + platformType + "/" + firmwareName + ".tar.gz"
        #os.remove(pathToFirmware)

    return success


# delete firmware with respect to mac address and firmware name
def deleteFirmwareRespecttoMac(request,macAddr, firmwareName):
    table = defineTableName(request)
    scanResponse = table.scan(
        ProjectionExpression="MacAddr,Firmware,PlatformType,GroupID",
        FilterExpression=Key("MacAddr").eq(macAddr) & Key("Firmware").eq(firmwareName),
    )

    item = scanResponse["Items"][0]

    mac = item["MacAddr"]
    firmware = item["Firmware"]
    platform = item["PlatformType"]
    GroupID = item["GroupID"]


    return deleteFileFromDb(request,table, mac, firmware, platform,GroupID)


# since updating a sort key is not allowed,first delete the item
# then add it again with firmware being 'empty'
def deleteFileFromDb(request,table, mac, firmware, platform,GroupID):
    try:
        table.delete_item(
            Key={
                'MacAddr': mac,
                'Firmware': firmware,
            },
        )
        table.put_item(
            Item={
                'MacAddr': mac,
                'PlatformType': platform,
                'GroupID': GroupID,
                'Firmware': 'empty',
                'StartLog' : '0',
                'Archived' : False,
                'Situation': 'empty',
                'StatusTime' : 'empty',
                'md5sum' : 'empty'
            }
        )
    except:
        return False
    return True

#END OF DYNAMODB QUERIES
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------!


"""
     Takes the binary name and returns its bare name
     without any version and archived extension
"""

def getNameWithoutVersion(filename):
    filename = str(filename)
  # assign filename directly in case of not archived
    nameWithoutVersion = filename

  # archived file

    if filename.endswith("tar.gz"):
            tarStartIndex = filename.find("tar")
            nameWithoutVersion = filename[:tarStartIndex - 1]

    dotIndex = nameWithoutVersion.find(".")

    if isVersioned(filename):
          # get only name without version (blapot-controller from blapot-controller-0.1.1)
            nameWithoutVersion = nameWithoutVersion[:dotIndex - 2]

    return nameWithoutVersion

"""
+    Checks whether given filename contains
+    versions as a pattern of (x.x.x)
+    where x is a digit (i.e 1.0.2)
"""



def isVersioned(filename):
    dotIndex = filename.find(".")

    versioned = False

      # contains dot so check
      # if version pattern satisfied (x.x.x)

    if dotIndex != -1:

        if filename[dotIndex - 1].isdigit() and filename[dotIndex + 1].isdigit() and filename[dotIndex + 3].isdigit():
                        versioned = True
    return versioned


def getSlashIndex(filename):
    index = 0
    for i, character in enumerate(filename):
        if character == '-':
            index = i
    return index


def getVersion(filename):
    return filename[getSlashIndex(filename) + 1:]


def getFirmwareName(filename):
    return filename[:getSlashIndex(filename)]


def find_nth(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start + len(needle))
        n -= 1
    return start


"""
    it is the endpoint that daemons send request
    gets necessary fields from request
    gets items from db with respect to sent elements
    calculates necesary information and returns it as a json
"""


def checkForDefault(platformType, existingBinaries):
    defaultDir = "./bin/default/"
    platformDir = defaultDir + platformType

    toBeUpdatedBinaries = []
    binariesArchived = []

    try:
        platforms = os.listdir(platformDir)
        for firmware in platforms:
            archived = False
            # check whether firmware is archived or not
            if firmware.find("tar") == -1:
                firmwareNoExt = firmware
            else:
                firmwareNoExt = firmware[:firmware.find("tar") - 1]
                archived = True
            if firmwareNoExt not in existingBinaries:
                toBeUpdatedBinaries.append(firmwareNoExt)
                binariesArchived.append(archived)
    except:
        toBeUpdatedBinaries = []
        binariesArchived = []

    return toBeUpdatedBinaries,binariesArchived

"""
    Create the firmware zip under a directory
    named by mac address of the requester blaumd
"""


def createFirmwareZip(toBeUpdatedBinaries, binariesArchived, binaryDir, firmwareZipDir):
    # create zip storage directory
    if not os.path.exists(firmwareZipDir):
        os.mkdir(firmwareZipDir)
    firmwareZipPath = firmwareZipDir + "/firmware.zip"
      # create zip file to be returned
    zipFilePtr = zipfile.ZipFile(firmwareZipPath, mode="w")

    for index, filename in enumerate(toBeUpdatedBinaries):
                firmwareName = filename
      # check if the binary is archived(tar.gz extension) or not
                if binariesArchived[index]:
                        firmwareName = filename + ".tar.gz"
                # write binary to the zip
                zipFilePtr.write(os.path.join(binaryDir, firmwareName), firmwareName)


"""
    Returns the firmware zip file which is stored
    under a directory named by a mac address of the
   requester blaumd.
    Also puts the requester mac address to a globally
    defined set in order to notify firmware zip watcher thread
    to get them removed.
"""



def return_file(request):
    if request.method == 'POST':
        try:
            # get mac adress of the requester blaumd
            json_data = json.loads(request.body)
            mac = json_data["main_mac"]
        except:
            return HttpResponse(json.dumps({}))

        try:
            firmwareDMMutex.acquire()
            # if there are more than 10 elements, notify watcher
            # in order to remove firmware zip storage directories
            if len(firmwareDownloadedMacs) > 10:
                firmwareDMCv.notifyAll()

            # wait if there are more than 10 elements
            while len(firmwareDownloadedMacs) > 10:
                firmwareDMCv.wait()
            # append mac adress to the array
            firmwareDownloadedMacs.add(mac)
            firmwareDMMutex.release()

            # path where firmware zip is stored
            firmwareZipStoragePath = "./bin/firmwares/" + mac + "/firmware.zip"

            f = open(firmwareZipStoragePath, 'rb')
            fileContent = f.read()
            f.close()
            return HttpResponse(fileContent, 'application/zip')
        except:
            print("Failed downloading")
            # in case of error, remove appended mac
            firmwareDMMutex.acquire()
            firmwareDownloadedMacs.discard(mac)
            firmwareDMMutex.release()
            return HttpResponse(json.dumps({}))
    else:
        return HttpResponse(json.dumps({}))

"""
    A watcher thread removes firmware zip storage
    directories when there are 10 directories
    (i.e 10 different blaumd requested and got update)

    This thread is notified when 10 different blaumd
    downloaded a new firmware zip file. Then this
    thread removes those directories that contain
    firmwares requested by blaumds.
"""
def firmwareZipWatcher():
    while(1):
        firmwareDMMutex.acquire()
        # wait until there is at least 10 elements
        while len(firmwareDownloadedMacs) < 10:
            firmwareDMCv.wait()

        print("Watcher Notified!")
        print("Following mac addresses' firmwares will be deleted")
        print(str(firmwareDownloadedMacs))

        # remove all firmware zip folders
        # whose firmwares already downloaded
        # by a blaumd
        for mac in firmwareDownloadedMacs:
            firmwareZipPath = "./bin/firmwares/" + mac
            if os.path.exists(firmwareZipPath):
                shutil.rmtree(firmwareZipPath)
        firmwareDownloadedMacs.clear()

        firmwareDMCv.notifyAll()
        firmwareDMMutex.release()

"""
+    Gets the version of the binary
+    by looking at its internal strings.
"""
def getVersionUsingScript(fileName,tempDir):
    filePath = tempDir + fileName

    tempDirForVersion = tempDir + "tempForVersion"
    archived = False
    # if archived, extract the file
    if fileName.endswith("tar.gz"):
        archived = True

        # extract archive
        tar = tarfile.open(filePath,"r:gz")
        tar.extractall(path=tempDirForVersion)

        # change file path to new extracted path
        # make filename bare binary
        filePath = tempDirForVersion + "/" + getNameWithoutVersion(fileName)

    command1 = subprocess.Popen(["strings",filePath],stdout=subprocess.PIPE)
    command2 = subprocess.Popen(["grep %s %s %s %s" %("-m 1","-E","-e '^[0-9]*\.[0-9]*\.[0-9]*-.*$'","-e '^[0-9]*\.[0-9]*\.[0-9]*$'")],stdin=command1.stdout,stdout=subprocess.PIPE,shell=True)
    stdout,stderr = command2.communicate()

    # remove temporarily created folder
    if archived:
        shutil.rmtree(tempDirForVersion,ignore_errors=True)

    version = stdout.decode("utf-8")
    version = version[:-1]
    return version

"""
    Gets the md5sum of the uploaded binary
    Returns md5sum of the binary if succedd
    In case of error returns "error" as a string
"""
def getmd5sumOfBinary(fileName,tempDir):
    md5sum = "error"
    try:
        filePath = tempDir + fileName
        tempDirForVersion = tempDir + "tempForVersion"
        archived = False
        if fileName.endswith("tar.gz"):
            archived = True

            # extract archive
            tar = tarfile.open(filePath,"r:gz")
            tar.extractall(path=tempDirForVersion)

            # change file path to new extracted path
            # make filename bare binary
            filePath = tempDirForVersion + "/" + getNameWithoutVersion(fileName)

        # command to get md5sum of the uploaded file
        command = subprocess.Popen(["md5sum",filePath],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        stdout,stderr = command.communicate()

        result = stdout.decode("utf-8")
        result = str(result)
        md5sum = result.split(" ")[0]

        # remove temporarily created folder
        if archived:
            shutil.rmtree(tempDirForVersion,ignore_errors=True)
    except:
        print('error md5sum')
        md5sum = "error"

    return md5sum

#Auto Create folders which exists in S3 bucket
def bucketfolders(request):
    client = boto3.resource(
        'dynamodb',
        aws_access_key_id='',
        aws_secret_access_key='',
        region_name='',
    )

    s3 = boto3.resource('s3')
    tempDir = "./bin/"
    my_bucket = s3.Bucket('blaums-c')
    mys3_files = []
    file_arr = []
    for file in my_bucket.objects.all():
        file_arr.append(file)
    for index, s3_file in enumerate(my_bucket.objects.all()):
        foldername = os.path.dirname(s3_file.key)
        defDir = tempDir + "/" + "default"
        mys3_files.append(foldername)
        s3files = np.asarray(mys3_files)
        if len(file_arr) - 1 == index:
            print(list(numpy.unique(s3files)))
        if not os.path.exists(defDir):
            os.mkdir(defDir)
            print("DEFAULT FOLDER WAS CREATED!")
        if not os.path.exists(tempDir + foldername):
            os.mkdir(tempDir + foldername)
            print(tempDir + foldername + " WAS CREATED FROM S3-BUCKET (blaums-c)")
        else:
            if len(file_arr) - 1 == index:
                print("*THE FOLDERS WHICH IN ARRAY EXISTS IN LOCAL BIN FOLDER AND S3-BUCKET (blaums-c) !")
                print()

    print("Downloading all the binaries from amazon...")
    # download files into current directory
    for s3_object in my_bucket.objects.all():
        # Need to split s3_object.key into path and file name, else it will give error file not found.
        path, filename = os.path.split(s3_object.key)
        if filename != "":
            filePath = tempDir + path + "/" + filename
            if not os.path.exists(filePath):
                my_bucket.download_file(s3_object.key, filePath)
    print("Downloaded all the binaries from amazon")

    # create firmware zip storage directory under where firmware zip
    # files created (i.e bin/firmwares directory)
    try:
        firmwareZipDir = "./bin/firmwares"
        # first remove the directory
        # to avoid from not removed files getting accumulated
        if os.path.exists(firmwareZipDir):
            shutil.rmtree(firmwareZipDir)
        os.mkdir(firmwareZipDir)
        print("Firmware zip storage directory created")
    except:
        print("Failed creating firmware zip storage directory")

#--------------------------------------THE FUNCTIONS IN ORDER TO GET REQUEST FROM blaUMD-------------------------------------------------------!
def send_json(request):
    if request.method == 'POST':

        json_data = json.loads(request.body)
        print(json_data)
        try:
            toBeUpdatedBinaries = []
            binariesArchived = []

            existingBinaries = json_data["existing_binaries"]
            targetMac = json_data["main_mac"]
            platformType = json_data["platform_id"]

            table = defineTableName(request)

            response = table.scan(
                ProjectionExpression="Firmware,StartLog,Archived",
                FilterExpression=Key("MacAddr").eq(targetMac),
            )
        except:
            return HttpResponse(json.dumps({}))

        firmwareDictArr = response["Items"]

        # loop over firmwares belong to the given mac addressed daemon
        for firmwareDict in firmwareDictArr:
            firmware = firmwareDict["Firmware"]
            archived = firmwareDict["Archived"]
            if firmware not in existingBinaries and firmware != 'empty':
                toBeUpdatedBinaries.append(firmware)
                binariesArchived.append(archived)

        binDir = "./bin/"
        isDefault = False
        if len(toBeUpdatedBinaries) == 0:
            if len(firmwareDictArr) == 0:
                isDefault = True
                toBeUpdatedBinaries,binariesArchived = checkForDefault(platformType, existingBinaries)

            elif len(firmwareDictArr) == 1:
                firmwareDict = firmwareDictArr[0]

                if firmwareDict["Firmware"] == "empty":
                    isDefault = True
                    toBeUpdatedBinaries,binariesArchived = checkForDefault(platformType, existingBinaries)
        signatures = []
        for index,firmware in enumerate(toBeUpdatedBinaries):
            # check for bare binary
            firmwarePath = binDir + platformType + "/" + firmware

            # if not bare binary check for archived file
            if(binariesArchived[index]):
                firmwarePath = binDir + platformType + "/" + firmware + ".tar.gz"

            if isDefault:
                firmwarePath = binDir + "default/" + platformType + "/" + firmware
                if not os.path.exists(firmwarePath):
                    firmwarePath = binDir + "default/" + platformType + "/" + firmware + ".tar.gz"

            privateKeyFile = "fd.key"
            privateKeyFilePass = b"bla5665"

            try:
                keyFile = open(privateKeyFile, "r")
                key = keyFile.read()
                keyFile.close()

                pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, privateKeyFilePass)

                dataFile = open(firmwarePath, "rb")
                data = dataFile.read()
                dataFile.close()
            except:
                return HttpResponse(json.dumps({}))

            sign = OpenSSL.crypto.sign(pkey, data, "sha256")
            dataBase64 = base64.b64encode(sign)
            dataBase64 = dataBase64.decode("utf-8")
            signatures.append(dataBase64)

        responseJSon = {}
        current_url = request.META['HTTP_HOST'] + '/firmware'
        if len(toBeUpdatedBinaries) == 0:
            responseJSon["result"] = "unavailable"
            responseJSon["log"] = firmwareDictArr
        else:
            responseJSon["result"] = "available"
            responseJSon["info"] = toBeUpdatedBinaries
            responseJSon["log"] = firmwareDictArr
            responseJSon["url"] = current_url
            responseJSon["signature"] = signatures

        firmwareDir = binDir + platformType
        if isDefault:
            firmwareDir = binDir + "default/" + platformType

        try:
            if len(toBeUpdatedBinaries) != 0:
                firmwareZipDir = binDir + "firmwares/" + targetMac
                createFirmwareZip(toBeUpdatedBinaries, binariesArchived, firmwareDir, firmwareZipDir)
            print(responseJSon)
            return HttpResponse(json.dumps(responseJSon))
        except:
            return HttpResponse(json.dumps({}))

def statusJson(request):
    if request.method == 'POST':
        status_json = json.loads(request.body)
        print(status_json)

        try:
            existingBinaries = status_json["existing_binaries"]
            binaryStatus = status_json["binary_status"]
            targetMac = status_json["main_mac"]
            platformType = status_json["platform_id"]
        except:
            return HttpResponse(json.dumps({}))


        now = datetime.datetime.now()
        timestamp = int(datetime.datetime.timestamp(now))


        try:
            table = defineTableName(request)


            for (i, binary) in enumerate(existingBinaries):
                response = table.get_item(Key = {
                    'MacAddr'  : targetMac,
                    'Firmware' : binary,
                })

                # update the necessary fields
                item = response["Item"]
                item["Situation"] = binaryStatus[i]
                item["StatusTime"] = timestamp
                table.put_item(Item=item)
        except:
            return HttpResponse(json.dumps({}))
    return HttpResponse(json.dumps({}))
#------------------------------------------------------------------------END OF FUNCTIONS FOR blaUMD-----------------------------------------------------------------------------!



#Authentication functions:
def loginfirst(request):

        if request.method == 'POST':
            user = request.POST.get('change_username')
            passw = request.POST.get('change_password')
            data = {"username": user, "password": passw,"token": request.session['reset_token']}
            encoded_data = json.dumps(data).encode('utf-8')
            http = urllib3.PoolManager()
            response = http.request(method='POST',url="https://gb06lbj7si.execute-api.eu-central-1.amazonaws.com/prod/changepassword",body=encoded_data,headers={"Content-Type": "application/json"})
            response = json.loads(response.data.decode('utf-8'))
            print(response)
            if response['statusCode'] == 200:
                request.session.pop('reset_token')
                response_login = http.request(method='POST',
                                        url="https://gb06lbj7si.execute-api.eu-central-1.amazonaws.com/prod/authentication",
                                        body=encoded_data, headers={"Content-Type": "application/json"})

                response_login = json.loads(response_login.data.decode('utf-8'))
                if response_login['statusCode'] == 200:
                    request.session['token'] = response_login['data']['IdToken']
                    request.session['name'] = response_login['data']['name']
                    request.session['role'] = response_login['data']['role']
                    request.session['partner_name'] = response_login['data']['partner_name']
                    request.session['partner_id'] = response_login['data']['partner_id']
                    request.session['username'] = response_login['data']['username']
                    request.session['email'] = response_login['data']['email']
                    request.session['AccessToken'] = response_login['data']['AccessToken']
                    request.session['tzone'] = response_login['data']['time_zone']
                    request.session['RefreshToken'] = response_login['data']['RefreshToken']
                    request.session.set_expiry(settings.SESSION_COOKIE_AGE) #It saves expire time to cookies.
                    return redirect('/cloud/upload/')
                else:
                    return redirect('/loginfirst')


        return render(request,'changepassword.html')

def loginpage(request):

    if request.method == 'POST':
        message = 'The username or password is incorrect'
        username = request.POST.get('login_username')
        password = request.POST.get('login_password')
        data = {"username": username, "password": password}
        encoded_data = json.dumps(data).encode('utf-8')
        http = urllib3.PoolManager()
        response = http.request(method='POST',url="https://gb06lbj7si.execute-api.eu-central-1.amazonaws.com/prod/authentication",body=encoded_data,headers={"Content-Type": "application/json"})
        response = json.loads(response.data.decode('utf-8'))
        print(response)
        status = response['statusCode']
        if status == 200:
            print('logged')
            print(response['data']['IdToken'])
            request.session['token'] = response['data']['IdToken']
            request.session['name'] = response['data']['name']
            request.session['role'] = response['data']['role']
            request.session['partner_name'] = response['data']['partner_name']
            request.session['partner_id'] = response['data']['partner_id']
            request.session['username'] = response['data']['username']
            request.session['email'] = response['data']['email']
            request.session['AccessToken'] = response['data']['AccessToken']
            request.session['tzone'] = response['data']['time_zone']
            request.session['RefreshToken'] = response['data']['RefreshToken']
            request.session.set_expiry(settings.SESSION_COOKIE_AGE) #It saves expire time to cookies.
            return redirect('/')
        elif status == 201:
            request.session['reset_token'] = response['reset_token']

            return redirect('/loginfirst')
            #return render(request, 'loginpage.html', {'status': status , 'change_username' : username})
        else:

            return render(request, 'loginpage.html', {'message': message})
    else:
        return render(request,'loginpage.html' )

def forgot_request(request):
    if request.method == 'POST':
        user = request.POST.get('forgot_username')
        data = {'username' : user}
        encoded_data = json.dumps(data).encode('utf-8')
        http = urllib3.PoolManager()
        response = http.request(method='POST',
                               url="https://gb06lbj7si.execute-api.eu-central-1.amazonaws.com/prod/forgotpassword",
                               body=encoded_data, headers={"Content-Type": "application/json"})

        response = json.loads(response.data.decode('utf-8'))
        if response['statusCode'] == 200:
            return redirect('/resetpassw')
        else:
            return render(request,'sendverification.html', )
    return render(request, 'sendverification.html', )


def confirmation_request(request):
    if request.method == 'POST':
        user = request.POST.get('confirmation_username')
        confcode = request.POST.get('confirmation_code')
        password = request.POST.get('confirmation_password')
        repeat_password = request.POST.get('repeat_confirmation_password')
        data = {"username": user, "confcode": confcode, "password": password}
        encoded_data = json.dumps(data).encode('utf-8')
        http = urllib3.PoolManager()
        if password != repeat_password:
            return render(request,'resetpassword.html')
        else:
            response = http.request(method='POST',url="https://gb06lbj7si.execute-api.eu-central-1.amazonaws.com/prod/forgotpasswordconfirmation",
                                    body=encoded_data, headers={"Content-Type": "application/json"})
            response = json.loads(response.data.decode('utf-8'))
            if response['statusCode'] == 200:
                return redirect('/loginpage')
            else:
                return render(request,'resetpassword.html')

    return render(request, 'resetpassword.html')


def logout(request):
        print(request.session.get('role'))
        if request.method == "GET":
            print('get')
            request.session.pop('RefreshToken')
            request.session.pop('tzone')
            request.session.pop('AccessToken')
            request.session.pop('email')
            request.session.pop('username')
            request.session.pop('partner_id')
            request.session.pop('partner_name')
            request.session.pop('role')
            request.session.pop('name')
            request.session.pop('token')
            request.COOKIES.pop('csrftoken')
            request.COOKIES.pop('sessionid')
            request.COOKIES.clear()
            request.session.clear()
            request.session.flush()
        for i in range(2):
            if request.method == "POST":
                        request.session.pop('RefreshToken')
                        request.session.pop('tzone')
                        request.session.pop('AccessToken')
                        request.session.pop('email')
                        request.session.pop('username')
                        request.session.pop('partner_id')
                        request.session.pop('partner_name')
                        request.session.pop('role')
                        request.session.pop('name')
                        request.session.pop('token')
                        request.COOKIES.pop('csrftoken')
                        request.COOKIES.pop('sessionid')
                        request.COOKIES.clear()
                        request.session.clear()
                        request.session.flush()
            else:
                return redirect('/loginpage')
#END OF AUTHENTICATION FUNCTIONS
#----------------------------------------------------------------------------------------------!



#FUNCTIONS OF PLATFORM,MAC ADDRESS ADDING ,UPLOAD,LOG LIST,DELETE FIRMWARE OR PLATFORM-MAC FORMS.
def home_view(request):

    sessionvalue = request.session.get('role')
    if sessionvalue == 'super':
        return render(request, 'intro.html', {'sessionvalue': sessionvalue})
    else:
        return redirect('/loginpage')


# When a new mac adress added with platform type
def fform(request):
    # if this is a POST request we need to process the form data
    sessionvalue = request.session.get('role')
    if sessionvalue is None:
        return redirect('/loginpage')
    if sessionvalue == 'super':
        if request.method == 'POST' or request.is_ajax():
            # create a form instance and populate it with data from the request:
            form = FirmwareForm(request.POST, request.GET)
            MacAddr = request.POST.get('MacAddr', None)
            platformType = request.POST.get('platformType', None)
            GroupNum = request.POST.get('GroupIDS',None)

            MacAddr = str(MacAddr)
            MacAddr = MacAddr.lower()
            if MacAddr is None or platformType is None:
                return JsonResponse({"success": False}, status=400)

            if GroupNum is None:
                GroupNum = getGroupIdRespectPlatform(request,platformType)[0]['GroupID']

            table = defineTableName(request)


            try:
                table.put_item(
                    Item={
                        'MacAddr': MacAddr,
                        'PlatformType': platformType,
                        'GroupID' : GroupNum,
                        'Firmware': 'empty',
                        'StartLog' : '0',
                        'Archived' : False,
                        'Situation': 'empty',
                        'StatusTime' : 'empty',
                        'md5sum' : 'empty'
                    }
                )

                # create directory to store upcoming firmwares under the directory
                binDir = "./bin/"
                platforms = os.listdir(binDir)
                if platformType not in platforms:
                    platformPath = binDir + str(platformType)
                    os.mkdir(platformPath)

                defaultDirStr = "default"
                defaultDir = binDir + defaultDirStr
                if defaultDirStr not in platforms:
                    os.mkdir(defaultDir)

                platforms = os.listdir(defaultDir)
                if platformType not in platforms:
                    platformDefaultPath = defaultDir + "/" + str(platformType)
                    os.mkdir(platformDefaultPath)
                Firmware.objects.values_list('MacAddr', 'MacAddr').distinct()
                return JsonResponse({"success": True}, status=200)
            except:
                return render(request, 'macform.html', {'form': form}, status=400)
        # if a GET (or any other method) we'll create a blank form
        else:
            form = FirmwareForm()
            platformTypes = getPlatormTypes(request,unique=True)
        return render(request, 'macform.html', {'form': form ,'platformTypes': platformTypes,"sessionvalue": sessionvalue}, status=200)
    else:
        return redirect('/loginpage')

# Adding Platform
def addplatform(request):
    # if this is a POST request we need to process the form data
    sessionvalue = request.session.get('role')

    if sessionvalue is None:
        return redirect('/loginpage')
    if sessionvalue == 'super':
        if request.method == 'POST':
            # create a form instance and populate it with data from the request:
            form = FirmwareForm(request.POST, request.GET)
            GroupID = form.data["GroupID"]
            GroupID = str(GroupID)
            GroupID = GroupID.lower()
            platformType = form.data["PlatformType"]
            MacAddr = form.data["MacAddr"]
            MacAddr = str(MacAddr)
            MacAddr = MacAddr.lower()


            if GroupID.startswith(platformType + '-'):
                print('yes')
            else:
                print('no')
                return render(request, 'platformadd.html', {'form': form}, status=400)

            table = defineTableName(request)

            try:
                table.put_item(
                    Item={
                        'MacAddr': MacAddr,
                        'PlatformType': platformType,
                        'GroupID' : GroupID,
                        'Firmware': 'empty',
                        'StartLog' : '0',
                        'Archived' : False,
                        'Situation': 'empty',
                        'StatusTime' : 'empty',
                        'md5sum' : 'empty'
                    }
                )

                # create directory to store upcoming firmwares under the directory
                binDir = "./bin/"
                platforms = os.listdir(binDir)
                if platformType not in platforms:
                    platformPath = binDir + str(platformType)
                    os.mkdir(platformPath)

                defaultDirStr = "default"
                defaultDir = binDir + defaultDirStr
                if defaultDirStr not in platforms:
                    os.mkdir(defaultDir)

                platforms = os.listdir(defaultDir)
                if platformType not in platforms:
                    platformDefaultPath = defaultDir + "/" + str(platformType)
                    os.mkdir(platformDefaultPath)

                Firmware.objects.values_list('MacAddr', 'MacAddr').distinct()
                #Create folders when new platform type is added.
                store = boto3.client("s3")
                store.put_object(Bucket="blaums-c", Key=(platformType + '/'))
                store.put_object(Bucket="blaums-c", Key=("default/" + platformType + '/'))
                bucketfolders(request)
                return HttpResponseRedirect('/cloud/upload')
            except:
                return render(request, 'platformadd.html', {'form': form }, status=400)
        # if a GET (or any other method) we'll create a blank form
        else:
            form = FirmwareForm()
        return render(request, 'platformadd.html', {'form': form , "sessionvalue" : sessionvalue}, status=200)
    else:
        return redirect('/')

""" 
 uploads a file by either getting a new file or selecting existing one
 if new firmware uploaded it is stored under proper directory
 if a firmware already exists no new storage needed
 necessary properties updated or inserted a new item in a case in db
 if a firmware with same name uploaded by selecting the firmware
 it is updated in the proper directory

"""

def upload_default_file(request):
    defaultDir = "./bin/default/temp/"

    if request.session.get('role'):
        # first request containing files
        if request.method == 'POST' and request.FILES:
            myfile = request.FILES["file"]
            fs = FileSystemStorage(location=defaultDir)
            fs.save(myfile.name, myfile)
            return JsonResponse({"success": True}, status=200)

        # second request containing data
        if request.method == 'POST' and ("csrfmiddlewaretoken" not in request.POST):
            newFirmware = request.POST.get("filename", None)
            platformType = request.POST.get("platformType", None)

            if newFirmware is None or platformType is None:
                return JsonResponse({"success": False}, status=400)

            # get its no extension name
            newFirmware = str(newFirmware)
            if newFirmware.find("tar") == -1:
                newFirmwareNoExt = newFirmware
            else:
                newFirmwareNoExt = newFirmware[:newFirmware.find("tar") - 1]
            bareFirmware = getNameWithoutVersion(newFirmwareNoExt)

            # state whether uploaded firmware is archived or not
            archived = False
            if newFirmware.find("tar") != -1:
                archived = True

            # move preuploaded firmware to its proper location
            binDir = "./bin/default/"
            srcFirmwarePath = defaultDir + newFirmware
            destFirmwareDir = binDir + platformType

            newFirmwareWithVersion = newFirmwareNoExt
            # check if firmware is versioned (i.e daemon-0.1.1)
            if not isVersioned(newFirmware):
                # put version at the end of the file using script that gathers version from binary itself
                newFirmwareWithVersion = newFirmwareNoExt + "-" + getVersionUsingScript(newFirmware,defaultDir)

            destFirmwarePath = binDir + platformType + "/" + newFirmwareWithVersion
            if archived:
                destFirmwarePath = destFirmwarePath + ".tar.gz"

            # create platform directory if not exists
            defPlatformPath = binDir + platformType
            if not os.path.exists(defPlatformPath):
                os.mkdir(defPlatformPath)

            # upload default files to AMAZON S3
            store = boto3.resource("s3")
            try:
                platforms = os.listdir(destFirmwareDir)
                # remove old default firmware and write new one
                for platform in platforms:
                    if bareFirmware in platform:
                        localPath = destFirmwareDir + "/" + platform
                        s3Path = "default/" + platformType + "/" + platform
                        # remove old default from both local and s3
                        try:
                            os.remove(localPath)
                            store.Object('blaums-c',s3Path).delete()
                        except:
                            print("Can't remove the file")

                shutil.move(srcFirmwarePath, destFirmwarePath)
                # upload the new default to the s3

                directPath = "default" + "/" + platformType + "/" + newFirmwareWithVersion
                if archived:
                    directPath = "default" + "/" + platformType + "/" + newFirmwareWithVersion + '.tar.gz'

                store.meta.client.upload_file(destFirmwarePath, 'blaums-c', directPath)

                return JsonResponse({"success": True}, status=200)
            except:
                return JsonResponse({"success": False}, status=400)
    else:
        return redirect('/loginpage')

def upload_file(request):
        sessionvalue = request.session.get('role')
        if sessionvalue is None:

            return redirect('/loginpage')
        tempDir = "./bin/temp/"
        if sessionvalue == 'super':
            client = boto3.resource(
                'dynamodb',
                aws_access_key_id='',
                aws_secret_access_key='',
                region_name='',
            )
            store = boto3.resource('s3')
            # first request containing files
            if request.method == 'POST' and request.FILES:
                myfile = request.FILES["file"]
                fs = FileSystemStorage(location=tempDir)
                fs.save(myfile.name, myfile)
                return JsonResponse({"success": True}, status=200)

            # second request containing data
            if request.method == 'POST' and ("csrfmiddlewaretoken" not in request.POST):
                form = FirmwareForm(request.POST or None, request.FILES or None )
                macList = request.POST.get("macList", None)
                newFirmware = request.POST.get("filename", None)
                isNewFirmware = request.POST.get("newFile", None)
                platformType = request.POST.get("platformType", None)
                GroupID = request.POST.get("GroupID",None)

                if macList is None or newFirmware is None or isNewFirmware is None or platformType is None:
                    return JsonResponse({"success": False}, status=400)
                macListJson = json.loads(macList)
                macListArr = macListJson["selected"]
                # if a new firmware uploaded,get its no extension name
                newFirmware = str(newFirmware)
                if isNewFirmware is not None and isNewFirmware == "true":
                    if newFirmware.find("tar") == -1:
                        newFirmwareNoExt = newFirmware
                    else:
                        newFirmwareNoExt = newFirmware[:newFirmware.find("tar") - 1]
                    # state whether uploaded firmware is archived or not
                    archived = False
                    if newFirmware.find("tar") != -1:
                        archived = True
                else:
                    archiveInfo = getArchivedRespectoFirmware(request,newFirmware)[0]['Archived']
                    archived = False
                    if archiveInfo == True:
                        archived = True
                    newFirmwareNoExt = newFirmware
                bareFirmware = getNameWithoutVersion(newFirmwareNoExt)
                # move preuploaded firmware to its proper location
                binDir = "./bin/"
                srcFirmwarePath = tempDir + newFirmware
                destFirmwareDir = binDir + platformType

                newFirmwareWithVersion = newFirmwareNoExt
                  # check if firmware is versioned (i.e daemon-0.1.1)

                if not isVersioned(newFirmware):
                      # put version at the end of the file using script that gathers version from binary itself
                    newFirmwareWithVersion = newFirmwareNoExt + "-" + getVersionUsingScript(newFirmware, tempDir)

                destFirmwarePath = binDir + platformType + "/" + newFirmwareWithVersion

                # get md5sum of the uploaded binary
                md5sum = getmd5sumOfBinary(newFirmware,tempDir)
                if not md5sum:
                    md5sum = getmd5sumOfBinary(newFirmware,destFirmwareDir + '/')
                    #when in uploaded firmwares list have firmware but it doesnt has .zip, its simple binary.
                    if not md5sum:
                        md5sum = getmd5sumOfBinary(newFirmware + '.tar.gz', destFirmwareDir + '/')
                        if not md5sum:
                            md5sum = 'N/A'
                #if firmware selected from uploaded firmwares list.
                if archived:
                    destFirmwarePath = destFirmwarePath + ".tar.gz"

                platformPath = binDir + platformType
                if not path.exists(platformPath):
                    os.mkdir(platformPath)
                # Upload folder file to AMAZON-S3

                directPath = platformType + "/" + newFirmwareWithVersion
                if archived:
                    directPath = platformType + "/" + newFirmwareWithVersion + '.tar.gz'
                #if its new firmware or exists firmware(from firware list in upload form)
                try:
                    platforms = os.listdir(destFirmwareDir)
                    # if a filename selected from the list,insblad of uploading a new one
                    if isNewFirmware is not None and isNewFirmware == "true":
                        if not bareFirmware.endswith('controller'):
                            if not bareFirmware.endswith('cloud-daemon'):
                                return JsonResponse({"success": False}, status=400)
                        # if new firmware exists ,rewrite it.otherwise move it
                        if newFirmware in platforms:
                            existFilePath = binDir + platformType + "/" + newFirmware
                            #store.meta.client.upload_file(existFilePath, 'blaums-c', directPath)
                        shutil.move(srcFirmwarePath, destFirmwarePath)
                        os.chmod(destFirmwarePath, 0o777)
                        store.meta.client.upload_file(destFirmwarePath, 'blaums-c', directPath)
                except:
                    return JsonResponse({"success": False,"versionedFirmware":newFirmwareWithVersion}, status=400)

                table = defineTableName(request)

                for mac in macListArr:
                    try:

                       #when Group ID is selected from list
                       if GroupID is not None:
                           deleteResponse = table.delete_item(
                               Key={
                                   'MacAddr': mac,
                                   'Firmware': 'empty',
                               },
                               ReturnValues='ALL_OLD'
                           )

                           # if first time a mac added
                           if "Attributes" in deleteResponse:
                               oldAttr = deleteResponse["Attributes"]
                               platformType = oldAttr['PlatformType']
                               GroupID = oldAttr['GroupID']
                           else:
                               # mac with another firmware
                               platformType = request.POST.get("platformType", None)
                               GroupID = request.POST.get("GroupID", None)
                               # check if there is an old item
                               scanResponse = table.scan(
                                   ProjectionExpression="Firmware",
                                   FilterExpression=Key("Firmware").begins_with(bareFirmware) & Key("MacAddr").eq(mac),
                               )

                               # check if the item needs to be updated
                               if scanResponse["Items"]:
                                   oldItem = scanResponse["Items"][0]
                                   oldFirmware = oldItem["Firmware"]
                                   deleteResponse = table.delete_item(
                                       Key={
                                           'MacAddr': mac,
                                           'Firmware': oldFirmware
                                       },
                                   )
                           # put new item
                           putResponse = table.put_item(
                               Item={
                                   'MacAddr': mac,
                                   'Firmware': newFirmwareWithVersion,
                                   'PlatformType': platformType,
                                   'GroupID' : GroupID,
                                   'StartLog': '0',
                                   'Archived': archived,
                                   'Situation': 'empty',
                                   'StatusTime': 'empty',
                                   'md5sum' : md5sum
                               }
                           )

                       #When Group ID is not selected
                       else:
                           print('GROUP IS NOT SELECTED')
                           GroupNum = getGroupRespectoMac(request,mac)
                           GroupNumber = GroupNum[0]["GroupID"]
                           deleteResponse = table.delete_item(
                               Key={
                                   'MacAddr': mac,
                                   'Firmware': 'empty',
                               },
                               ReturnValues='ALL_OLD'
                           )

                           # if first time a mac added
                           if "Attributes" in deleteResponse:
                               oldAttr = deleteResponse["Attributes"]
                               platformType = oldAttr['PlatformType']
                               GroupIDS = oldAttr['GroupID']
                           else:
                               # mac with another firmware
                               platformType = request.POST.get("platformType", None)
                               GroupIDS = GroupNumber
                               # check if there is an old item
                               scanResponse = table.scan(
                                   ProjectionExpression="Firmware",
                                   FilterExpression=Key("Firmware").begins_with(bareFirmware) & Key("MacAddr").eq(mac),
                               )

                               # check if the item needs to be updated
                               if scanResponse["Items"]:
                                   oldItem = scanResponse["Items"][0]
                                   oldFirmware = oldItem["Firmware"]
                                   deleteResponse = table.delete_item(
                                       Key={
                                           'MacAddr': mac,
                                           'Firmware': oldFirmware
                                       },
                                   )


                           # put new item
                           putResponse = table.put_item(
                               Item={
                                   'MacAddr': mac,
                                   'Firmware': newFirmwareWithVersion,
                                   'PlatformType': platformType,
                                   'GroupID': GroupIDS,
                                   'StartLog': '0',
                                   'Archived': archived,
                                   'Situation': 'empty',
                                   'StatusTime': 'empty',
                                    'md5sum' : md5sum
                               }
                           )
                    except:
                        print('except side')
                        return JsonResponse({"success": False,"versionedFirmware":newFirmwareWithVersion}, status=400)
                return JsonResponse({"success": True,"versionedFirmware":newFirmwareWithVersion}, status=200)
            else:
                form = FirmwareForm()
                platformTypes = getPlatormTypes(request,unique=True)
                return render(request, 'uploadform.html', {'form': form, "platformTypes": platformTypes, 'sessionvalue' : sessionvalue })
        else:
            return redirect('/loginpage')

"""
    updates the log level of the binaries
    for now handles all the binaries
    belong to only 'one' mac
"""
def loglist(request):
    sessionvalue = request.session.get('role')

    if sessionvalue is None:
        return redirect('/loginpage')
    if sessionvalue == 'super':
        if request.method == 'POST':
            platformType = request.POST.get("platformType",None)
            macAddr = request.POST.get('macList',None)
            Firm = request.POST.get('firmware',None)
            StartLog = request.POST.get('LogLevel',None)

            macListJson = json.loads(macAddr)
            macListArr = macListJson["selected"]
            FirmJson = json.loads(Firm)
            firmwares = FirmJson

            try:
                # get only first mac
                mac = macListArr[0]

                table = defineTableName(request)


                # loop over the binaries to update the log status of the selected binaries
                for index, firmware in enumerate(firmwares):
                    response = table.get_item(Key = {
                        'MacAddr'  : mac,
                        'Firmware' : firmware,
                    })
                    # only update the log level field
                    item = response["Item"]
                    item["StartLog"] = StartLog
                    table.put_item(Item=item)
            except:
                return JsonResponse({"success": False}, status=400)
            return JsonResponse({"success": True}, status=200)
        else:
            form = FirmwareForm()
            platformTypes = getPlatormTypes(request,unique=True)
            firminfo = getFirmwares(request,unique=True)

            return render(request, 'list.html' ,{'form' : form,'platformTypes':platformTypes , 'firminfo' : firminfo , 'sessionvalue' : sessionvalue})

    else:
        return redirect('/loginpage')

def delete_platform(request):
    sessionvalue = request.session.get('role')

    if sessionvalue is None:
        return redirect('/loginpage')
    if sessionvalue == 'super':
        form = FirmwareForm()
        platformTypes = getPlatormTypes(request,unique=True)

        if request.method == 'POST':
            platformType = request.POST.get("platformType", None)
            mac = request.POST.get("mac", None)

            if platformType is None or mac is None:
                return render(request, 'platformdelete.html', {'form': form, "platformTypes": platformTypes},
                              status=400)

            macs = json.loads(mac)

            if len(macs) == 0:
                if not deletePlatform(request,platformType):
                    return render(request, 'platformdelete.html', {'form': form, "platformTypes": platformTypes},
                                  status=400)
            else:
                for mac in macs:
                    if not deleteMacAddress(request,platformType, mac):
                        return render(request, 'platformdelete.html', {'form': form, "platformTypes": platformTypes},
                                      status=400)

        return render(request, 'platformdelete.html', {'form': form, "platformTypes": platformTypes , "sessionvalue" : sessionvalue}, status=200)
    else:
        return redirect('/')


"""
    deletes firmware from db and from storage if necessary
    in case of deleting a firmware from platform 
    the field of the firmware in that platform made 'empty' and the firmware removed
    from storage
    in case of deleting a firmware for mac address
    only its field made 'empty'
"""


def delete_firmware(request):
    sessionvalue = request.session.get('role')

    if sessionvalue is None:
        return redirect('/loginpage')
    if sessionvalue == 'super':

        form = FirmwareForm()
        platformTypes = getPlatormTypes(request,unique=True)
        if request.method == 'POST':

            data = request.POST

            platformType = data.get("platformType", None)
            mac = data.get("mac", None)
            firmwares = data.get("firmware", None)
            GroupID = data.get("GroupID",None)

            macs = json.loads(mac)
            firmwares = json.loads(firmwares)

            # delete firmware with respect to platform
            if len(macs) == 0:
                for firmware in firmwares:
                    if firmware != 'empty':
                        if not deleteFirmwareRespecttoPlatform(request,platformType, firmware):
                            return render(request, 'firmwaredelete.html',
                                          {'form': form, "platformTypes": platformTypes},
                                          status=400)
            else:
                # delete firmwares with respect to macs
                for firmware in firmwares:
                    if firmwares != 'empty':
                        for mac in macs:
                            if not deleteFirmwareRespecttoMac(request,mac, firmware):
                                return render(request, 'firmwaredelete.html',
                                              {'form': form, "platformTypes": platformTypes },
                                              status=400)

            return render(request, 'firmwaredelete.html', {'form': form, "platformTypes": platformTypes,"sessionvalue":sessionvalue}, status=200)
        else:
            return render(request, 'firmwaredelete.html', {'form': form, "platformTypes": platformTypes, "sessionvalue":sessionvalue },status=400)
    else:
        return redirect('/loginpage')

#END OF ALL FORMS FUNCTIONS---------------------------------------------------------------------------------------------------------------------!



#THE FUNCTIONS IN ORDER TO USE FOR AJAX-JAVASCRIPT FOR GET DATA INSTANT
def firmPanel(request):
    firminfo = getFirmwares(request)
    if firminfo is None:
        return render(request, "list.html", status=400)
    else:
        return render(request, "list.html", {"firminfo":firminfo})

def groupPanelInfo1(request):
    if request.method == "POST" or request.is_ajax():
        if request.POST:
            platformType = request.POST.get('platformType')
            groups = request.POST.get('groups[]')
            macs = getMacAddress(request,groups)
            firmware = request.POST.get('firminfo')
            macRespectFirm = getMacAddresses(request,firmware)
            firmRespectoMac = getFirmwaresRespectoMac(request,macs)
            groupRespectFirm = getGroupRespectoFirm(request,firmware)
            platformRespectFirm = getPlatformRespectFirm(request,firmware)
            return JsonResponse({"macs":macs , "platformType" : platformType , "macRespectFirm":macRespectFirm , "groupRespectFirm" : groupRespectFirm , 'platformRespectFirm' : platformRespectFirm ,'firmRespectoMac':firmRespectoMac},status=200)

    return JsonResponse({"success": False},status=400)

def groupPanelInfo(request):
    if request.method == "POST" or request.is_ajax():
        if request.POST:
            platformType = request.POST.get('platformType')
            groups = request.POST.get('groups[]')
            macs = getMacAddress(request,groups)
            firmware = request.POST.get('firminfo')
            macRespectFirm = getMacAddresses(request,firmware)
            firmRespectoMac = getFirmwaresRespectoMac(request,macs)
            groupRespectFirm = getGroupRespectoFirm(request,firmware)
            platformRespectFirm = getPlatformRespectFirm(request,firmware)
            return JsonResponse({"macs":macs , "platformType" : platformType , "macRespectFirm":macRespectFirm , "groupRespectFirm" : groupRespectFirm , 'platformRespectFirm' : platformRespectFirm ,'firmRespectoMac':firmRespectoMac},status=200)

    return JsonResponse({"success": False},status=400)

def firmwarePanelInfo(request):
    if request.method == "POST" or request.is_ajax():
        if request.POST:
            macs = request.POST.get('macs[]')
            firmwares = getFirmwaresRespectoMac(request,macs)
            Situation = getSituationRespectoMac(request,macs)
            StatusTime = getStatusTimeRespectoMac(request,macs)
            StartLog = getLogLevelRespectoMac(request,macs)
            GroupID = getGroupRespectoMac(request,macs)
            md5Info = getMd5RespectoMac(request,macs)
            if firmwares is None:
                return JsonResponse({"success": False}, status=400)

            return JsonResponse({"firmwares": firmwares, "Situation": Situation, "StatusTime": StatusTime, "StartLog": StartLog , "GroupID" : GroupID , "md5Info" : md5Info}, status=200)
    return JsonResponse({"success": False}, status=400)


def getDefaultFirmwares(request,platformType):
    defaultDir = "./bin/default/" + platformType

    try:
        defaultFirmwares = os.listdir(defaultDir)
        return defaultFirmwares
    except:
        return None

# FBV
def macPanel(request):
        platformTypes = getPlatormTypes(request,unique=True)
        if platformTypes is None:
            return render(request, "uploadform.html", status=400)
        else:
            return render(request, "uploadform.html", {"platformTypes": platformTypes})


def macPanelInfo(request):
    if request.method == "POST" or request.is_ajax():
        platformType = request.POST.get('platformType', None)
    if platformType is not None and str(platformType) != "":

        groupNumbers = getGroupIdRespectPlatform(request,platformType,unique=True)


        #groupArr = []
#        for group in groupNumbers:
 #           groupArr.append(int(group["GroupID"]))

        macAddresses = getMacAddr(request,platformType)
        #macAddr = getMacAddress(groupNumbers)
        firmwares = getFirmwaresRespectPlatform(request,platformType, unique=True)
        defaultFirmwares = getDefaultFirmwares(request,platformType)
        defaultFirmwaresJson = {"default": defaultFirmwares}
        if macAddresses is None or firmwares is None or groupNumbers is None:
            return JsonResponse({"success": False}, status=400)  # FBV

        return JsonResponse(
            {"groupNumbers" : groupNumbers, "macAddresses": macAddresses, "firmwares": firmwares, "default_firmwares": defaultFirmwaresJson },
            status=200)
    else:
        return JsonResponse({"success": False}, status=400)  # FBV





