from __future__ import absolute_import

import os
from django.conf import settings

from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _

async def image_validate_file_extension(value):
    valid_extensions = ['.jpeg', '.jpg', '.png']
    validator = FileExtensionValidator(allowed_extensions=valid_extensions)
    try:
        validator(value)
    except ValidationError as e:
        raise ValidationError(_('File type is not supported. Supported file types are: .pdf, .doc, .docx'))

async def document_validate_file_extension(value):
    valid_extensions = ['.pdf', '.doc', '.txt']
    validator = FileExtensionValidator(allowed_extensions=valid_extensions)
    try:
        validator(value)
    except ValidationError as e:
        raise ValidationError(_('File type is not supported. Supported file types are: .pdf, .doc, .docx'))


async def validate_credit_card(value):
    import requests

    url = "https://check-credit-card.p.rapidapi.com/detect"

    payload = value
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": settings.RAPID_API_KEY,
        "X-RapidAPI-Host": "check-credit-card.p.rapidapi.com"
    }

    response = await requests.post(url, json=payload, headers=headers)
    return response
