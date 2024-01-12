from rest_framework import serializers

from ..models import Banks, UserBankAccount, Wallet

class BanksSerializer(serializers.ModelSerializer):
    """
    Serializer for the Banks model.

    Fields:
    - name: The name of the bank.
    - slug: The slug of the bank.
    - lcode: The lcode of the bank.
    - code: The code of the bank.
    - country_iso: The ISO code of the country.

    Meta:
    - model: Banks
    - fields: ['name', 'slug', 'lcode', 'code', 'country_iso', "url]
    """

    class Meta:
        model = Banks
        fields = ["id", "name", "slug", "lcode", "code", "country_iso", "created", "modified", "url"]
        extra_kwargs = {"url": {"view_name": "api:bank-detail", "lookup_field": "slug"}}


class UserBankAccountSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserBankAccount model.

    Fields:
    - verified: Boolean field indicating if the user's bank account is verified.
    - bank: The associated Banks instance for the user's bank.
    - account_number: Encrypted field for storing the user's account number.
    - routing_number: Encrypted field for storing the user's routing number.
    - account_name: Encrypted field for storing the user's account name.
    - sort_code: Encrypted field for storing the user's sort code.

    Meta:
    - model: UserBankAccount
    - fields: ['verified', 'bank', 'account_number', 'routing_number', 'account_name', 'sort_code']
    - read_only_fields: ['user']
    """

    username = serializers.CharField(source="user.username", read_only=True)
    bank_name = serializers.CharField(source="bank.name", read_only=True)

    class Meta:
        model = UserBankAccount
        fields = ["id", 'username', "verified", "bank", "bank_name", "account_number", "routing_number", "account_name", "sort_code", "created", "modified", "url"]
        read_only_fields = ["id", 'verified', "created", "modified"]
        extra_kwargs = {"url": {"view_name": "api:bankaccount-detail", "lookup_field": "id"}}


class UserWalletSerializer(serializers.ModelSerializer):
    """Serializer for displaying the user's Wallet balance

    Fields:
    - balance: Decimal/Float field for balance
    """
    class Meta:
        model = Wallet
        fields = ['balance']
