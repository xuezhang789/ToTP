from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class UsernameOrEmailBackend(ModelBackend):
    """Allow login via username or case-insensitive email.

    Exact usernames take precedence over email matches so the same identifier
    cannot authenticate different users depending on the password provided.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        user_model = get_user_model()
        identifier = username if username is not None else kwargs.get(user_model.USERNAME_FIELD)
        if identifier is None or password is None:
            return None

        user = super().authenticate(request, username=identifier, password=password, **kwargs)
        if user is not None:
            return user

        if user_model._default_manager.filter(**{user_model.USERNAME_FIELD: identifier}).exists():
            return None

        try:
            user = user_model._default_manager.get(email__iexact=identifier)
        except (user_model.DoesNotExist, user_model.MultipleObjectsReturned):
            user_model().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
