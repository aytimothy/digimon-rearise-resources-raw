#!/usr/bin/env python3

import argparse
import base64
from collections import deque
from Crypto.Cipher import AES, XOR
import hashlib
import json
import os
import posixpath
import queue
import re
import requests
import sys
import threading
import traceback
from urllib3.util.retry import Retry
import zlib

KEY = b'fK%Bcy6EgzAQsR-a/LNDUt!cAZNG97a&'
def decrypt_aes(data):
	plaintext = AES.new(KEY, AES.MODE_CBC, data[2:18]).decrypt(data[20:])
	return plaintext[:-plaintext[-1]]
def decrypt_xor(data):
	return XOR.new(KEY).decrypt(data)

session = requests.Session()
retry = Retry(total=20, backoff_factor=0.01, status_forcelist=[502], method_whitelist=False)
session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retry))
def get(url):
	with print_lock:
		print(f'Getting {url}...')
	r = session.get(url, timeout=30)
	r.raise_for_status()
	if 'charset' not in r.headers['content-type'].lower():
		r.encoding = 'utf-8-sig'
	return r

def cache_key(value):
	if not re.match(r'^[0-9a-f]{32}$', value):
		raise argparse.ArgumentTypeError('invalid cache key: ' + value)
	return value
parser = argparse.ArgumentParser()
parser.add_argument('--global', action='store', dest='global_lang',
                    choices=('en', 'ko', 'zh'))
parser.add_argument('resource_cache_key', type=cache_key)
args = parser.parse_args()
del parser

cache_key = args.resource_cache_key

if args.global_lang:
	base_url = 'https://digirige-os-cache.channel.or.jp/resource/'
	lang = url_lang = args.global_lang
else:
	base_url = 'https://cache.digi-rise.com/resource'
	lang = 'ja'
	url_lang = ''

digest_by_path = {}
path_by_digest = {}
try:
	with open('decrypted.blake2b') as file:
		for line in file:
			digest, path = line.rstrip('\n').split('  ', 1)
			digest_by_path[path] = digest
			path_by_digest[digest] = path
except FileNotFoundError:
	print('BLAKE2b cache not found. Overwriting all assets...', file=sys.stderr)
except Exception as e:
	print(f'Failed to load BLAKE2b cache: {e!r}. Overwriting all assets...', file=sys.stderr)
	digest_by_path = {}
	path_by_digest = {}

print_lock = threading.Lock()

n_decrypting_threads = 2
decryptable_queue = queue.Queue(64)
decrypting_threads = []
def decrypt_repeatedly():
	while True:
		data = decryptable_queue.get()
		if data is SystemExit:
			break
		name, crc, encrypted, data = data
		if crc is not None and zlib.crc32(data) != crc:
			with print_lock:
				print(f'Mismatched CRC for {name}:', file=sys.stderr)
				continue
		try:
			if encrypted:
				data = decrypt_xor(data)
		except BaseException as e:
			with print_lock:
				print(f'Failed to decrypt {name}:', file=sys.stderr)
				traceback.print_exc()
		else:
			digest = hashlib.blake2b(data).hexdigest()
			path = posixpath.join(lang, name)
			if digest != digest_by_path.get(path):
				os.makedirs(os.path.dirname(path), exist_ok=True)
				other_path = path_by_digest.get(digest)
				if other_path is not None:
					os.link(other_path, path + '.part')
				else:
					with open(path + '.part', 'wb') as file:
						file.write(data)
				os.replace(path + '.part', path)
				digest_by_path[path] = digest
				path_by_digest[digest] = path
for i in range(n_decrypting_threads):
	t = threading.Thread(target=decrypt_repeatedly, daemon=True)
	decrypting_threads.append(t)
	t.start()

n_downloading_threads = 64
downloadable_queue = queue.Queue(64)
downloading_threads = []
def download_repeatedly():
	while True:
		resource = downloadable_queue.get()
		if resource is SystemExit:
			break
		resource, resource_kind, encrypted, split = resource
		downloaded_name = name = posixpath.join(resource_kind, resource['name'])
		try:
			dirname = posixpath.dirname(resource['name'])
			url = posixpath.join(base_url, url_lang, cache_key, resource_kind, dirname, resource['hash'])
			if split is None:
				data = get(url).content
			else:
				data = []
				for i in range(1, 1 + (resource['size'] + split - 1) // split):
					try:
						data.append(get(f'{url}.{i:03d}').content)
					except:
						downloaded_name = f'{name}.{i:03d}'
						raise
				data = b''.join(data)
		except BaseException as e:
			with print_lock:
				print(f'Failed to download {downloaded_name}:', file=sys.stderr)
				traceback.print_exc()
		else:
			decryptable_queue.put((name, resource['crc'], encrypted, data))
for i in range(n_downloading_threads):
	t = threading.Thread(target=download_repeatedly, daemon=True)
	downloading_threads.append(t)
	t.start()

MANIFEST_HASH = '7f5cb74af5d7f4b82200738fdbdc5a45'  # md5('manifest')

resource_kinds = [
	('asset/android', True, None),
	('asset/ios', True, None),
]
if args.global_lang:
	resource_kinds += [
		('sound/jp', False, None),
		('sound/en', False, None),
		('movie/jp', False, 4194304),
		('movie/en', False, 4194304),
	]
else:
	resource_kinds += [
		('sound', False, None),
		('movie', False, 4194304),
	]

for resource_kind, encrypted, split in resource_kinds:
	try:
		with open(os.path.join(lang, resource_kind, 'manifest')) as file:
			old_asset_manifest = json.load(file)
	except FileNotFoundError:
		old_asset_manifest = {'resources': ()}

	url = posixpath.join(base_url, url_lang, cache_key, resource_kind, MANIFEST_HASH)
	manifest = get(url).content

	try:
		manifest = base64.b64decode(manifest, validate=True)
	except ValueError:
		pass

	try:
		manifest = decrypt_aes(manifest)
	except ValueError:
		pass

	manifest = json.loads(manifest)

	for resource in manifest['resources']:
		if posixpath.isabs(resource['name']):
			raise ValueError('resource path is absolute: ' + resource['name'])
		if '/.' in resource['name'] or resource['name'].startswith('.'):
			raise ValueError('resource path contains dot-filenames: ' + resource['name'])
		if '.part/' in resource['name'] or resource['name'].endswith('.part'):
			raise ValueError('resource path contains filenames ending in .part: ' + resource['name'])
		if resource in old_asset_manifest['resources']:
			# Sanity check in case a previous instance of this script crashed
			try:
				if os.path.getsize(os.path.join(lang, resource_kind, resource['name'])) == resource['size']:
					continue
			except OSError:
				pass
		downloadable_queue.put((resource, resource_kind, encrypted, split))

	path = os.path.join(lang, resource_kind, 'manifest')
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path + '.part', 'w', encoding='utf-8') as file:
		json.dump(manifest, file, ensure_ascii=False, indent='\t')
		file.write('\n')
	os.replace(path + '.part', path)

i = 1
opening_movie_data = []
while True:
	name = f'builtin/m.{i:03d}'
	try:
		url = posixpath.join(base_url, url_lang, cache_key, name)
		data = get(url).content
	except BaseException as e:
		with print_lock:
			print(f'Failed to download {name}:', file=sys.stderr)
			traceback.print_exc()
		break
	else:
		opening_movie_data.append(data)
	if len(data) < 4000000:
		decryptable_queue.put(('builtin/m', None, False, b''.join(opening_movie_data)))
		break
	i += 1
del opening_movie_data

for t in downloading_threads:
	downloadable_queue.put(SystemExit)
for t in downloading_threads:
	t.join()

for t in decrypting_threads:
	decryptable_queue.put(SystemExit)
for t in decrypting_threads:
	t.join()

path = 'decrypted.blake2b'
with open(path + '.part', 'w', encoding='utf-8') as file:
	for digested_path, digest in sorted(digest_by_path.items()):
		print(f'{digest}  {digested_path}', file=file)
os.replace(path + '.part', path)
