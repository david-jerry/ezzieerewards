from django.db.models import (
    CharField,
    ForeignKey,
    CASCADE,
    DecimalField,
    SlugField,
    OneToOneField,
    BooleanField,
)
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

# from model_utils import FieldTracker
from model_utils.models import TimeStampedModel
from encrypted_fields.fields import EncryptedCharField

User = get_user_model()

class Wallet(TimeStampedModel):
    """
    Represents a user's wallet, tracking their balance and transaction history.

    Attributes:
        user (OneToOneField): A one-to-one relationship with the User model, representing the owner of the wallet.
        balance (DecimalField): Decimal field storing the current balance of the wallet, with a maximum of 20 digits (including 2 decimal places).

    Methods:
        str(self): Returns a string representation of the wallet, formatted as "{user.name} Wallet".

    Meta:
        verbose_name (str): Singular human-readable name for the model, used in the admin interface.
        verbose_name_plural (str): Plural human-readable name for the model, used in the admin interface.
        ordering (list): Specifies the default ordering of wallets in queries, based on the user's ID.
    """
    user = OneToOneField(User, on_delete=CASCADE, related_name="wallet")
    balance = DecimalField(max_digits=20, decimal_places=2, default=0)

    def __str__(self):
        """
        String representation of the User's wallet instance.

        Returns:
        - str: String representation.
        """
        return f"{self.user.name} Wallet"

    class Meta:
        verbose_name = _("Wallet")
        verbose_name_plural = _("Wallets")
        ordering = ["user__id"]

class Banks(TimeStampedModel):
    """
    Represents a bank institution, storing its essential details.

    Attributes:
        name (CharField): The full name of the bank, with a maximum length of 500 characters and a unique constraint to ensure no duplicates.
        slug (SlugField): A unique URL-friendly slug generated from the bank's name, used for creating clean and consistent URLs.
        lcode (CharField): Optional long code associated with the bank, with a maximum length of 25 characters and a database index for efficient lookups.
        code (CharField): Optional short code associated with the bank, with a maximum length of 10 characters and a database index for efficient lookups.
        country_iso (CharField): The ISO 3166-1 alpha-2 country code representing the bank's country of operation, with a maximum length of 10 characters.

    Methods:
        str(self): Returns a string representation of the bank, using its name.

    Meta:
        verbose_name (str): Singular human-readable name for the model, used in the admin interface.
        verbose_name_plural (str): Plural human-readable name for the model, used in the admin interface.
        ordering (list): Specifies the default ordering of banks in queries, first by name and then by country_iso.
    """
    name = CharField(max_length=500, unique=True)
    slug = SlugField(unique=True)
    lcode = CharField(max_length=25, db_index=True, blank=True, null=True)
    code = CharField(max_length=10, db_index=True, blank=True, null=True)
    country_iso = CharField(max_length=10)

    def __str__(self):
        """
        String representation of the Banks instance.

        Returns:
        - str: String representation.
        """
        return self.name

    class Meta:
        verbose_name = _("Bank")
        verbose_name_plural = _("Banks")
        ordering = ["name", "country_iso"]

class UserBankAccount(TimeStampedModel):
    """
    Represents a user's bank account information, prioritizing secure storage and verification.

    Attributes:
        user (OneToOneField): A one-to-one relationship with the User model, ensuring a single bank account record for each user.
        verified (BooleanField): Indicates whether the user's bank account has been successfully verified, enhancing trust and security.
        bank (ForeignKey): Links to the associated Banks model, providing context about the specific financial institution.
        account_number (EncryptedCharField): Securely stores the user's account number, employing encryption for robust protection.
        routing_number (EncryptedCharField): Securely stores the user's routing number, similarly encrypted for confidentiality.
        account_name (EncryptedCharField): Securely stores the name associated with the bank account, upholding privacy.
        sort_code (EncryptedCharField): Stores an optional sort code, if applicable in the user's region, for financial routing purposes.

    Methods:
        str(self): Returns a user-friendly representation of the bank account, identifying it as belonging to the respective user.

    Meta:
        verbose_name (str): Provides a singular human-readable name for the model, used in the admin interface for clarity.
        verbose_name_plural (str): Provides a plural human-readable name for the model, ensuring consistency in admin interfaces.
        ordering (list): Specifies a default ordering of bank accounts by their modification time, prioritizing recent updates.
    """
    user = OneToOneField(User, on_delete=CASCADE, related_name="bank_account")
    verified = BooleanField(default=False)
    bank = ForeignKey("Banks", on_delete=CASCADE, default=8, related_name="bank_accounts")
    account_number = EncryptedCharField(max_length=20, blank=True, null=True)
    routing_number = EncryptedCharField(max_length=20, blank=True, null=True)
    account_name = EncryptedCharField(max_length=255, blank=True, null=True)
    sort_code = EncryptedCharField(max_length=20, blank=True, null=True)

    def __str__(self):
        """
        String representation of the User's Bank Account instance.

        Returns:
        - str: String representation.
        """
        return f"Bank Account for {self.user.username}"

    class Meta:
        verbose_name = "User Bank Account"
        verbose_name_plural = "Users Bank Accounts"
        ordering = ["-modified"]


