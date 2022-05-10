#!/usr/bin/env python3

import argparse
import base64
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor as XOR
import fcntl
import hashlib
import json
import os
import posixpath
import queue
import re
import requests
import sys
import tempfile
import threading
import traceback
from urllib3.util.retry import Retry
import zlib

if hasattr(fcntl, 'F_FULLFSYNC'):
	def fsync(file):
		try:
			fcntl.fcntl(file.fileno(), fcntl.F_FULLFSYNC)
		except OSError:
			os.fsync(file.fileno())
else:
	def fsync(file):
		os.fsync(file.fileno())

KEY = b'fK%Bcy6EgzAQsR-a/LNDUt!cAZNG97a&'
def decrypt_aes(data):
	plaintext = AES.new(KEY, AES.MODE_CBC, data[2:18]).decrypt(data[20:])
	return plaintext[:-plaintext[-1]]
def decrypt_xor(data):
	return XOR(data, KEY)

session = requests.Session()
retry = Retry(total=20, backoff_factor=0.01, status_forcelist=[502], allowed_methods=False)
session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retry))
def get(url):
	with print_lock:
		print(f'Getting {url}...')
	with session.get(url, timeout=30) as r:
		r.raise_for_status()
		return r.content

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
		digest_cache_mtime = os.fstat(file.fileno()).st_mtime_ns
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

def file_needs_overwrite(path, digest):
	if digest != digest_by_path.get(path):
		return True
	try:
		# Sanity check in case a previous instance of this script crashed
		return os.stat(path).st_mtime_ns > digest_cache_mtime
	except OSError:
		with print_lock:
			print(f'stat() failed for known file {path}:', file=sys.stderr)
			traceback.print_exc()
		return True

n_decrypting_threads = 2
decryptable_queue = queue.Queue(16)
decrypting_threads = []
def decrypt_repeatedly():
	while True:
		data = decryptable_queue.get()
		if data is SystemExit:
			break
		name, crc, encrypted, data, resource, resource_kind, split, attempt = data
		if crc is not None:
			try:
				if zlib.crc32(data) != crc:
					if attempt >= 5:
						with print_lock:
							print(f'Mismatched CRC for {name}', file=sys.stderr)
					else:
						downloadable_queue.put((resource, resource_kind, encrypted, split, attempt + 1))
					continue
			finally:
				downloadable_queue.task_done()
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
			if file_needs_overwrite(path, digest):
				os.makedirs(os.path.dirname(path), exist_ok=True)
				other_path = path_by_digest.get(digest)
				with tempfile.TemporaryDirectory(dir=os.path.dirname(path),
				                                 prefix=f'._{posixpath.basename(name)}') as tempdir:
					temppath = os.path.join(tempdir, posixpath.basename(name))
					if other_path is not None:
						os.link(other_path, temppath)
					else:
						with open(temppath, 'wb') as file:
							file.write(data)
							file.flush()
							fsync(file)
					os.replace(temppath, path)
				digest_by_path[path] = digest
				path_by_digest[digest] = path
		finally:
			del data
for i in range(n_decrypting_threads):
	t = threading.Thread(target=decrypt_repeatedly, daemon=True)
	decrypting_threads.append(t)
	t.start()

n_downloading_threads = 16
downloadable_queue = queue.Queue()
downloading_threads = []
def download_repeatedly():
	while True:
		resource = downloadable_queue.get()
		if resource is SystemExit:
			break
		resource, resource_kind, encrypted, split, attempt = resource
		downloaded_name = name = posixpath.join(resource_kind, resource['name'])
		try:
			dirname = posixpath.dirname(resource['name'])
			url = posixpath.join(base_url, url_lang, cache_key, resource_kind, dirname, resource['hash'])
			if split is None:
				data = get(url)
			else:
				data = []
				for i in range(1, 1 + (resource['size'] + split - 1) // split):
					try:
						data.append(get(f'{url}.{i:03d}'))
					except:
						downloaded_name = f'{name}.{i:03d}'
						raise
				data = b''.join(data)
		except BaseException as e:
			if attempt >= 5:
				with print_lock:
					print(f'Failed to download {downloaded_name}:', file=sys.stderr)
					traceback.print_exc()
			else:
				downloadable_queue.put((resource, resource_kind, encrypted, split, attempt + 1))
			downloadable_queue.task_done()
		else:
			decryptable_queue.put((name, resource['crc'], encrypted, data, resource, resource_kind, split, attempt))
		finally:
			del data
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
			old_asset_manifest_resources = {resource['name']: resource for resource in json.load(file)['resources']}
	except FileNotFoundError:
		old_asset_manifest_resources = {}

	url = posixpath.join(base_url, url_lang, cache_key, resource_kind, MANIFEST_HASH)
	manifest = get(url)

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
		if resource['name'] in ('manifest', 'manifest.part'):
			raise ValueError('resource path clashes with manifest path')
		if resource == old_asset_manifest_resources.get(resource['name']):
			# Sanity check in case a previous instance of this script crashed
			try:
				if os.path.getsize(os.path.join(lang, resource_kind, resource['name'])) == resource['size']:
					continue
			except OSError:
				pass
		downloadable_queue.put((resource, resource_kind, encrypted, split, 1))

	path = os.path.join(lang, resource_kind, 'manifest')
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path + '.part', 'w', encoding='utf-8') as file:
		json.dump(manifest, file, ensure_ascii=False, indent='\t')
		file.write('\n')

i = 1
opening_movie_data = []
while True:
	name = f'builtin/m.{i:03d}'
	try:
		url = posixpath.join(base_url, url_lang, cache_key, name)
		data = get(url)
	except Exception:
		with print_lock:
			print(f'Failed to download {name}:', file=sys.stderr)
			traceback.print_exc()
		break
	else:
		opening_movie_data.append(data)
	if len(data) < 4000000:
		decryptable_queue.put(('builtin/m', None, False, b''.join(opening_movie_data), None, None, None, 1))
		break
	i += 1
del opening_movie_data

downloadable_queue.join()
for t in downloading_threads:
	downloadable_queue.put(SystemExit)
for t in downloading_threads:
	t.join()

for t in decrypting_threads:
	decryptable_queue.put(SystemExit)
for t in decrypting_threads:
	t.join()

for resource_kind, encrypted, split in resource_kinds:
	path = os.path.join(lang, resource_kind, 'manifest')
	with open(path + '.part', 'r+b') as file:
		fsync(file)
	os.replace(path + '.part', path)

path = 'decrypted.blake2b'
with open(path + '.part', 'w', encoding='utf-8') as file:
	for digested_path, digest in sorted(digest_by_path.items()):
		print(f'{digest}  {digested_path}', file=file)
	file.flush()
	fsync(file)
os.replace(path + '.part', path)
