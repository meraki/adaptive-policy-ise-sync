from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model


UserModel = get_user_model()


def run(username, token, reset_token=True):
    user = UserModel._default_manager.get_by_natural_key(username)

    if reset_token:
        Token.objects.filter(user=user).delete()

    t = Token.objects.get_or_create(user=user, key=token)
    print("API Token", t[0], "imported successfully!")
