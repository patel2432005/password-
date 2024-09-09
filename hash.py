import hashlib
import os
import pickle
import itertools
import string


DICTIONARY_FILE = "C:/Users/91878/wordlist.txt"  
RAINBOW_TABLE_FILE = "C:/Users/91878/rainbow_table.pkl"

def hash_password(password, hash_type):
    hash_func = getattr(hashlib, hash_type)()
    hash_func.update(password.encode())
    return hash_func.hexdigest()

def create_rainbow_table(dictionary_file, hash_type, rainbow_table_file):
    rainbow_table = {}
    try:
        with open(dictionary_file, 'r') as file:
            for line in file:
                word = line.strip()
                hashed_word = hash_password(word, hash_type)
                rainbow_table[hashed_word] = word

        with open(rainbow_table_file, 'wb') as table_file:
            pickle.dump(rainbow_table, table_file)
            
        print(f"[+] Rainbow table created and saved to {rainbow_table_file}")
    except FileNotFoundError:
        print(f"[-] The file {dictionary_file} was not found.")
    except AttributeError:
        print(f"[-] The hash type {hash_type} is not supported.")

def crack_password_with_rainbow_table(hash_to_crack, rainbow_table_file):
    try:
        with open(rainbow_table_file, 'rb') as table_file:
            rainbow_table = pickle.load(table_file)
        
        print(f"[+] Rainbow table loaded successfully. Attempting to crack hash {hash_to_crack}.")
        result = rainbow_table.get(hash_to_crack, None)
        if result:
            print(f"[+] Found password in rainbow table: {result}")
        else:
            print(f"[-] Password not found in rainbow table.")
        return result
    except FileNotFoundError:
        print(f"[-] The file {rainbow_table_file} was not found.")
        return None

def crack_password(hash_to_crack, dictionary_file, hash_type):
    try:
        with open(dictionary_file, 'r') as file:
            for line in file:
                word = line.strip()
                hashed_word = hash_password(word, hash_type)
                if hashed_word == hash_to_crack:
                    return word 
        return None  
    except FileNotFoundError:
        print(f"[-] The file {dictionary_file} was not found.")
        return None
    except AttributeError:
        print(f"[-] The hash type {hash_type} is not supported.")
        return None

def generate_password_combinations(password, max_length=10):
    characters = string.ascii_letters + string.digits + string.punctuation
    for length in range(1, max_length + 1):
        for combo in itertools.product(characters, repeat=length):
            yield ''.join(combo)

def guess_password_combinations(target_password):
    for guessed_password in generate_password_combinations(target_password):
        if guessed_password == target_password:
            return guessed_password
    return None

def main_menu():
    while True:
        print("\nMenu:")
        print("1. Crack Password from Hash")
        print("2. Create Rainbow Table")
        print("3. Crack Password with Rainbow Table")
        print("4. Guess Password Combinations")
        print("5. Exit")
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == "1":
            hash_to_crack = input("Enter the hash to crack: ").strip()
            hash_type = input("Enter the hash type (e.g., md5, sha1, sha256): ").strip()
            
            cracked_password = crack_password(hash_to_crack, DICTIONARY_FILE, hash_type)
            if cracked_password:
                print(f"Password is: {cracked_password}")
            else:
                print("Password could not be cracked.")
        
        elif choice == "2":
            hash_type = input("Enter the hash type (e.g., md5, sha1, sha256): ").strip()
            
            create_rainbow_table(DICTIONARY_FILE, hash_type, RAINBOW_TABLE_FILE)
        
        elif choice == "3":
            hash_to_crack = input("Enter the hash to crack: ").strip()
            
            cracked_password = crack_password_with_rainbow_table(hash_to_crack, RAINBOW_TABLE_FILE)
            if cracked_password:
                print(f"Password is: {cracked_password}")
            else:
                print("Password could not be cracked using the rainbow table.")
        
        elif choice == "4":
            target_password = input("Enter the password to guess: ").strip()
            guessed_password = guess_password_combinations(target_password)
            if guessed_password:
                print(f"Password is: {guessed_password}")
            else:
                print("Password could not be guessed.")
        
        elif choice == "5":
            print("Exiting the program.")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main_menu()
