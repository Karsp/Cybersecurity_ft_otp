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
		print(f"Decrypted secret: {secret}")
		
		# Convert hex secret to raw bytes
		# key_bytes = bytes.fromhex("66ac2ee810f3874c03d43688566ffa82eff464a61e3004ed1d3825aaacce9859")
		key_bytes = bytes.fromhex(secret.strip())

		# Calculate the Counter (8-byte binary)
		print(time.time())
		intervals_no = int(time.time() // 30)
		counter_bytes = struct.pack(">Q", intervals_no) # >Q means Big-Endian Unsigned Long Long

		# HMAC-SHA1  Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
		hmac_result = hmac.new(key_bytes, counter_bytes, hashlib.sha1).digest()

		# 4. Dynamic Truncation (The technical part)
		# Get the last 4 bits of the HMAC to use as an 'offset'
		offset = hmac_result[-1] & 0x0F
		
		# Grab 4 bytes starting from that offset
		truncated_hash = hmac_result[offset:offset + 4]
		
		# Convert to integer and mask the most significant bit (per RFC)
		code = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
		
		# Crop to 6 digits
		final_otp = code % 1000000
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

