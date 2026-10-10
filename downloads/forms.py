from django import forms
from django.conf import settings


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_clean = super().clean
        if isinstance(data, (list, tuple)):
            return [single_clean(item, initial) for item in data]
        return [single_clean(data, initial)]


class ScanForm(forms.Form):
    files = MultipleFileField(label="Files to check")

    def clean_files(self):
        files = [f for f in self.cleaned_data.get("files", []) if f]
        if not files:
            raise forms.ValidationError("Choose at least one file.")
        if len(files) > settings.SCAN_MAX_FILES:
            raise forms.ValidationError(
                f"Choose at most {settings.SCAN_MAX_FILES} files at a time.")
        limit = settings.SCAN_MAX_FILE_BYTES
        for f in files:
            if f.size > limit:
                raise forms.ValidationError(
                    f"{f.name} is larger than {limit // (1024 * 1024)} MB. "
                    "Use the downloadable scanner for big files.")
        return files
