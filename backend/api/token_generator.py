import random
import string

def generate_token():
    N = random.randint(1, 10)
    input_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
    hashed = hash(input_string)  # Using hash function to generate a numerical hash
    token = abs(hashed) % (10 ** 6)  # Get the absolute value and ensure it's 6 digits
    token_str = str(token).zfill(6)  # Convert to string and pad with zeros if necessary
    return token_str
