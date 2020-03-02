from django import forms

from firmware.models import *


class FirmwareForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super (FirmwareForm, self).__init__ (*args, **kwargs)
        self.fields['MacAddr'] = forms.CharField(label = 'Add New MAC Address',widget=forms.TextInput(attrs={'placeholder': 'Mac Address'}))
        self.fields['PlatformType'] = forms.CharField(label = 'Add New Platform Type',widget=forms.TextInput(attrs={'placeholder': 'Platform Type'}))
        self.fields['GroupID'] = forms.CharField(label = 'Add New Group Name',widget=forms.TextInput(attrs={'placeholder': 'Group Name'}),help_text='Group ID must start with Platform Name and dash like "x86-"!')



    class Meta:
        model = Firmware

        fields =('MacAddr','PlatformType','Firmware', 'GroupID','file' )




