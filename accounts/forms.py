from django import forms
from django.contrib.auth import get_user_model


User = get_user_model()


class ProfileForm(forms.ModelForm):
    """用于更新当前用户个人资料的表单。"""

    email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "name@example.com"}),
        label="邮箱",
    )
    first_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
        label="名",
    )
    last_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
        label="姓",
    )

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name"]

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        if not email:
            return ""
        if User.objects.exclude(pk=self.instance.pk).filter(email__iexact=email).exists():
            raise forms.ValidationError("该邮箱已被其他账号使用")
        return email
