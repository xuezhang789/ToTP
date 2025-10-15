import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm


User = get_user_model()

COMMON_WEAK_PASSWORDS = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "12345678",
    "123123",
    "qwertyuiop",
    "letmein",
    "admin",
    "welcome",
    "iloveyou",
    "dragon",
    "monkey",
    "login",
    "000000",
    "1q2w3e4r",
    "zaq12wsx",
}


def password_strength_errors(password: str, username: str = ""):
    """复用注册页的密码强度校验规则。"""

    errors: list[str] = []
    pwd = password or ""

    if len(pwd) < 8:
        errors.append("密码长度至少需要 8 个字符")

    categories = {
        "upper": bool(re.search(r"[A-Z]", pwd)),
        "lower": bool(re.search(r"[a-z]", pwd)),
        "digit": bool(re.search(r"\d", pwd)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", pwd)),
    }
    if sum(categories.values()) < 3:
        errors.append("密码需至少包含大写字母、小写字母、数字、符号中的三类")

    if re.search(r"\s", pwd):
        errors.append("密码不能包含空白字符")

    if username and username.lower() in pwd.lower():
        errors.append("密码不能包含用户名")

    if pwd and pwd.lower() in COMMON_WEAK_PASSWORDS:
        errors.append("密码与常见弱口令一致，请重新设置")

    return errors


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


class PasswordUpdateForm(PasswordChangeForm):
    """允许用户在资料页更新密码，并做本地强度校验。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_configs = {
            "old_password": ("当前密码", "请输入当前密码"),
            "new_password1": ("新密码", "至少 8 位，包含多种字符"),
            "new_password2": ("确认新密码", "再次输入新密码"),
        }
        for name, field in self.fields.items():
            label, placeholder = field_configs.get(name, ("", ""))
            attrs = {
                "class": "form-control",
                "placeholder": placeholder,
            }
            if name == "old_password":
                attrs["autocomplete"] = "current-password"
            else:
                attrs["autocomplete"] = "new-password"
            field.widget.attrs.update(attrs)
            if label:
                field.label = label

    def clean_new_password2(self):
        password = super().clean_new_password2()
        errors = password_strength_errors(password, username=self.user.username)
        if errors:
            raise forms.ValidationError(errors)
        return password
