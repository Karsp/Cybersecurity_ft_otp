#!/usr/bin/env python3

import sys
import os
import time
import argparse
import base64
import hashlib
from cryptography.fernet import Fernet
import hmac
import struct

class OTP:
	master_key = "Lalalalalala"

	def __init__(self):
		pass
	def __new__(cls):
		if not hasattr(cls, 'instance'):
			cls.instance = super(OTP, cls).__new__(cls)
		return cls.instance

	def get_content(self, input_string):
		# 1. Check if the string is a path to an existing file
		if os.path.isfile(input_string):
			try:
				with open(input_string, 'r') as f:
					# Read content and strip whitespace/newlines
					return f.read().strip()
			except Exception as e:
				print(f"Error reading file: {e}")
				return None
		# 2. If it's not a file, assume the string itself is the key
		return input_string.strip()

	def string_to_fernet_key(self, password: str) -> bytes:
			hashed = hashlib.sha256(password.encode()).digest() # Take the string and hash it with SHA-256 (always 32 bytes)
			return base64.urlsafe_b64encode(hashed) # Convert those 32 bytes to URL-safe base64

	def encrypt_and_save(self, hex_key_content: str):
		# calidar el contenido en hex y len
		def is_valid_hex(hex_key_content):
			dict_hex = "0123456789abcdefABCDEF"
			result = all(c in dict_hex for c in hex_key_content) and len(hex_key_content) >= 64
			return result

		if not is_valid_hex(hex_key_content):
			print("Invalid input.")
			return

		
		f = Fernet(self.string_to_fernet_key(self.master_key))
		data_to_encrypt = hex_key_content.encode() # Fernet only accepts bytes, so encode your hex string
		token = f.encrypt(data_to_encrypt) # Encrypt the data

		with open("ft_otp.key", "wb") as key_file:
			key_file.write(token)
		
		print("Key was successfully saved in ft_otp.key.")

	def generate_totp(self, key_path):
		# Get decrypted key from file
		f = Fernet(self.string_to_fernet_key(self.master_key))

		data_to_decrypt = self.get_content(key_path)
		secret = f.decrypt(data_to_decrypt) # Decrypt the data
		print(f"Decrypted secret: {secret.decode()}")

		# Calculate the Counter (8-byte binary)
		print(time.time())
		intervals_no = int(time.time() // 30)
		counter_bytes = struct.pack(">Q", intervals_no) # >Q means Big-Endian Unsigned Long Long

		# HMAC-SHA1  Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
		hmac_result = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

		# Dynamic Truncation (The technical part)
		# 1. Get the offset (last 4 bits of the last byte)
		offset = hmac_result[19] & 0xf
		
		# 2. Extract 4 bytes starting at offset
		p_bytes = hmac_result[offset : offset + 4]
		
		# 3. Convert to 32-bit integer (Big-Endian)
		p_num = struct.unpack(">I", p_bytes)[0]
		
		# 4. Mask the MSB (keep 31 bits)
		binary_code = p_num & 0x7fffffff
			
		# Crop to 6 digits
		final_otp = binary_code % 1000000
		return f"{final_otp:06d}" # Ensure leading zeros


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
		file_content = otp.get_content(args.g)
		otp.encrypt_and_save(file_content)
	elif args.k:
		otp_value = otp.generate_totp(args.k)
		print(f"Current OTP: {otp_value}")
		pass



if __name__ == '__main__':
	main()

