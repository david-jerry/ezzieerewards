from datetime import datetime
from slugify import slugify  # You may need to install this library using: pip install python-slugify

def generate_unique_slug(title):
    # Get the current datetime in numbers
    current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')

    # Combine title and datetime, then slugify the result
    raw_slug = f'{title} {current_datetime}'
    unique_slug = slugify(raw_slug)

    return unique_slug
