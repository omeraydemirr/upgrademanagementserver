from multiselectfield import MultiSelectField
import boto3
from django.contrib.contenttypes.models import *
from django.db.models import *
import os,re


class Firmware(models.Model):
    MacAddr = models.CharField  ("Mac Address",max_length = 120)
    Firmware = MultiSelectField("Firmware",max_length = 120)
    PlatformType = MultiSelectField("Platform Type",max_length = 200,null = True)
    file = models.FileField (verbose_name = 'File', upload_to = '')
    GroupID = models.CharField("Group ID" , max_length=200,null=True)

    def filename(self):
        return os.path.basename (self.file.name)
