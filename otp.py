#!/usr/bin/env python3

import sys
import os
import time
import argparse
import base64
import hashlib
from colorama import Fore, Style
from cryptography.fernet import Fernet



class OTP:
	master_key = "Lalalalalala"

	def __init__(self):
		pass
	def __new__(cls):
		if not hasattr(cls, 'instance'):
			cls.instance = super(OTP, cls).__new__(cls)
		return cls.instance
	def encrypt_and_save(self, hex_key_content: str):
		# calidar el contenido en hex y len
		def is_valid_hex(hex_key_content):
			dict_hex = "0123456789abcdefABCDEF"
			result = all(c in dict_hex for c in hex_key_content) and len(hex_key_content) >= 64
			return result

		if not is_valid_hex(hex_key_content):
			print("Invalid input.")
			return

		def string_to_fernet_key(password: str) -> bytes:
			hashed = hashlib.sha256(password.encode()).digest() # Take the string and hash it with SHA-256 (always 32 bytes)
			return base64.urlsafe_b64encode(hashed) # Convert those 32 bytes to URL-safe base64
		
		f = Fernet(string_to_fernet_key(self.master_key))
		data_to_encrypt = hex_key_content.encode() # Fernet only accepts bytes, so encode your hex string
		token = f.encrypt(data_to_encrypt) # Encrypt the data

		with open("ft_otp.key", "wb") as key_file:
			key_file.write(token)
		
		print("Key was successfully saved in ft_otp.key.")


def main():
	parser = argparse.ArgumentParser(
		description='TOTP - Time-based One-Time Password',
		usage='./ft_otp -g key.hex | ./ft_otp -k ft_otp.key'
	)

	parser.add_argument('-g', help='Generate a new OTP key from a hex file')
	parser.add_argument('-k', help='Use an existing OTP key file')

	args = parser.parse_args()

	# Validate arguments
	if not args.g and not args.k:
		parser.print_help()
		sys.exit(1)

	# Create OTP instance and run
	otp = OTP()
	if args.g:
		try:
			with open(args.g, 'r') as file:
				file_content = file.read()
			otp.encrypt_and_save(file_content)
		except FileNotFoundError:
			print("Error: File not found.")
		except Exception as e:
			print(f"Error: {e}")
	elif args.k:
		# Implement key loading logic here
		pass



if __name__ == '__main__':
	main()

