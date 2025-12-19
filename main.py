import argparse
import json
import os
import getpass
from cryptography.fernet import Fernet
import base64
import hashlib

DATA_FILE = 'passwords.enc'

def derive_key(master_password):
    # Derive encryption key from master password
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())

def load_data(master_password):
    # Load and decrypt stored data
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as f:
        encrypted = f.read()
    fernet = Fernet(derive_key(master_password))
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted)
    except:
        print("Invalid master password.")
        exit(1)

def save_data(data, master_password):
    # Encrypt and save data
    fernet = Fernet(derive_key(master_password))
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted)

def add_password(service, username, password, master_password):
    # Add or update a password entry
    data = load_data(master_password)
    data[service] = {'username': username, 'password': password}
    save_data(data, master_password)
    print(f"Password for '{service}' added/updated.")

def list_services(master_password):
    # List all stored services
    data = load_data(master_password)
    if data:
        print("Stored services:")
        for service in data:
            print(f"- {service}")
    else:
        print("No services stored.")

def get_password(service, master_password):
    # Retrieve username and password for a service
    data = load_data(master_password)
    if service in data:
        creds = data[service]
        print(f"Service: {service}")
        print(f"Username: {creds['username']}")
        print(f"Password: {creds['password']}")
    else:
        print(f"No entry found for '{service}'.")

def main():
    parser = argparse.ArgumentParser(description="Simple CLI Password Manager")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new password')
    add_parser.add_argument('--service', required=True, help='Service name')
    add_parser.add_argument('--username', required=True, help='Username')
    add_parser.add_argument('--password', required=True, help='Password')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all services')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get password for a service')
    get_parser.add_argument('--service', required=True, help='Service name')
    
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    
    master_password = getpass.getpass("Enter master password: ")
    
    if args.command == 'add':
        add_password(args.service, args.username, args.password, master_password)
    elif args.command == 'list':
        list_services(master_password)
    elif args.command == 'get':
        get_password(args.service, master_password)

if __name__ == "__main__":
    main()

"""
Usage:
- Add a password: python main.py add --service example.com --username user --password pass
- List services: python main.py list
- Get password: python main.py get --service example.com

Notes:
- Data is encrypted and stored in 'passwords.enc'.
- Use a strong master password.
- Install cryptography: pip install cryptography
"""
