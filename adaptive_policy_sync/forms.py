from django import forms
from django.forms import ModelForm
from sync.models import UploadZip


class UploadForm(ModelForm):
    description = forms.CharField(max_length=255, required=True, help_text='Certificate Description')
    file = forms.FileField()

    class Meta:
        model = UploadZip
        fields = ('description', 'file')
