"""Serializers for the user API View. They take JSON input (for example, from HTTP request), then check it (for example, if a password is long enough and then convert to Python objects or a model in a DB"""

from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext as _

from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user object"""

    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'name']
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        """Create and return a user with encrypted password"""
        return get_user_model().objects.create_user(**validated_data)


class AuthTokenSerializer(serializers.BaseSerializer):
    """Serializer for the user Auth token"""
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = password.get('password')

        user = authenticate(request=self.context.get('request'), username=email, password=password)

        if not user:
            msg = _('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs
