import random
import re
import string

from django.conf import settings

from .logger import LOGGER
import base64

def spotify_encode_to_base64():
    # Combine client_id and client_secret with a colon
    combined_credentials = f"{settings.SPOTIFY_ID}:{settings.SPOTIFY_SK}"

    # Encode the combined string to base64
    encoded_credentials = base64.b64encode(combined_credentials.encode('utf-8')).decode('utf-8')

    return encoded_credentials

def generate_random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))


from urllib.parse import urlparse

def extract_texts_from_spotify_link(spotify_link):
    parsed_url = urlparse(spotify_link)
    path_segments = parsed_url.path.split('/')

    # Find the index of 'user' in the path segments
    user_index = path_segments.index('user') if 'user' in path_segments else -1

    # If 'user' is present and there is a segment after it, return that segment
    if user_index != -1 and user_index + 1 < len(path_segments):
        return path_segments[user_index + 1]

    if not "https:/open.spotify.com" in spotify_link:
        return spotify_link

    # If 'user' is not found or there is no segment after it, return None
    return None

