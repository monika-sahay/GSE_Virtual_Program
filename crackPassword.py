import requests
import bcrypt
import hashlib



# Control 1: Use Stronger Hashing Algorithms
def hash_password(password):
    # Generate a salt and hash the password using bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Control 2: Salt the Hashes
def hash_password_with_salt(password, salt):
    # Hash the password using a provided salt using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Control 3: Use Key Stretching
def slow_hash_password(password, rounds=12):
    # Generate a salt and hash the password using bcrypt with custom number of rounds
    salt = bcrypt.gensalt(rounds=rounds)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def load_dictionary(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]


def analyze_password(hash_to_crack, dictionary):
    for password in dictionary:
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        if hashed_password == hash_to_crack:
            return password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        if sha1_hash == hash_to_crack:
            return password
    return None

def determine_hash_algorithm(hash_value):
    hash_length = len(hash_value)

    if hash_length == 16:
        return "MD5",hash_length
    elif hash_length == 20:
        return "SHA-1",hash_length
    elif hash_length == 32:
        return "MD5 or possibly other algorithms",hash_length
    elif hash_length == 40:
        return "SHA-1 or possibly other algorithms",hash_length
    elif hash_length == 64:
        return "SHA-256",hash_length
    elif hash_length == 96:
        return "SHA-384",hash_length
    elif hash_length == 128:
        return "SHA-512",hash_length
    else:
        return "Unknown",hash_length




if __name__ == '__main__':

    dictionary = load_dictionary("common_passwords.txt")
    # URL of the file
    url = "https://cdn.theforage.com/vinternships/companyassets/MBA4MnZTNFEoJZGnk/passwd_dump.txt"

    # Send an HTTP GET request to the URL
    response = requests.get(url)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Get the content of the response
        content = response.text.split()
        
        for hash_value in content:
            split_hash = hash_value.split(':')[-1]  # Extract hash part
            algorithm = determine_hash_algorithm(split_hash)
            
            cracked_password = analyze_password(split_hash, dictionary)

            print(f"Hash Value: {hash_value}  Algorithm: {algorithm}")
            if cracked_password:
                print(f"Password cracked: {cracked_password}")
                print('implimenting Stronger Hashing Algorithms')
                # Control 1: Use Stronger Hashing Algorithms (bcrypt)
                hashed_password_1 = hash_password(cracked_password)
                # Control 2: Salt the Hashes (using bcrypt)
                salt = bcrypt.gensalt()
                hashed_password_2 = hash_password_with_salt(cracked_password, salt)
                hashed_password_3 = slow_hash_password(cracked_password, rounds=15)
                print("Slow Hashed Password (bcrypt with key stretching):", hashed_password_3)
            else:
                print("Password not found in dictionary.")
                # Load dictionary

    else:
        print("Failed to fetch content from the URL")