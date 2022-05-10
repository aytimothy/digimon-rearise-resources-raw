#!/usr/bin/env python3

import json
import os
from random import randbytes
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor as XOR
from bs4 import BeautifulSoup
import requests
import argparse

# Settings
repo = "https://chortos.selfip.net/~astiob/digimon-rearise-resources/"
encrypt = False # Wait, do we even need to encrypt? // todo: Investigate server code.
KEY = b'fK%Bcy6EgzAQsR-a/LNDUt!cAZNG97a&'
pad = b'\x08'
iv = b'\x00'

parser = argparse.ArgumentParser()
parser.add_argument('--encrypt', action=argparse.BooleanOptionalAction, help="Whether to encrypt or not", dest="encrypt")
args = parser.parse_args()
del parser

if args.encrypt is not None:
    encrypt = args.encrypt

# Main Script
def decrypt_aes(data):
    plaintext = AES.new(KEY, AES.MODE_CBC, data[2:18]).decrypt(data[20:])
    return plaintext[:-plaintext[-1]]
def decrypt_xor(data):
    return XOR(data, KEY)
def encrypt_xor(data):
    return decrypt_xor(data)
def encrypt_aes(data, iv):
    padded = bytearray(data)
    while len(padded) % 16 != 0:
        padded.extend(pad)
    payload = AES.new(KEY, AES.MODE_CBC, iv).encrypt(padded)
    encrypted = bytearray(randbytes(2))
    encrypted.extend(iv)
    encrypted.extend(randbytes(2))
    encrypted.extend(payload)
    return encrypted

en_asset_android_manifest = json.load(open("./en/asset/android/manifest", "r"))
en_asset_ios_manifest = json.load(open("./en/asset/ios/manifest", "r"))
en_sound_en_manifest = json.load(open("./en/sound/en/manifest", "r"))
en_sound_jp_manifest = json.load(open("./en/sound/jp/manifest", "r"))
en_movie_en_manifest = json.load(open("./en/movie/en/manifest", "r"))
en_movie_jp_manifest = json.load(open("./en/movie/jp/manifest", "r"))
jp_asset_android_manifest = json.load(open("./ja/asset/android/manifest", "r"))
jp_asset_ios_manifest = json.load(open("./ja/asset/ios/manifest", "r"))
jp_movie_manifest = json.load(open("./ja/movie/manifest", "r"))
jp_sound_manifest = json.load(open("./ja/sound/manifest", "r"))
ko_asset_android_manifest = json.load(open("./ko/asset/android/manifest", "r"))
ko_asset_ios_manifest = json.load(open("./ko/asset/ios/manifest", "r"))
ko_sound_en_manifest = json.load(open("./ko/sound/en/manifest", "r"))
ko_sound_jp_manifest = json.load(open("./ko/sound/jp/manifest", "r"))
ko_movie_en_manifest = json.load(open("./ko/movie/en/manifest", "r"))
ko_movie_jp_manifest = json.load(open("./ko/movie/jp/manifest", "r"))
zh_asset_android_manifest = json.load(open("./zh/asset/android/manifest", "r"))
zh_asset_ios_manifest = json.load(open("./zh/asset/ios/manifest", "r"))
zh_sound_en_manifest = json.load(open("./zh/sound/en/manifest", "r"))
zh_sound_jp_manifest = json.load(open("./zh/sound/jp/manifest", "r"))
zh_movie_en_manifest = json.load(open("./zh/movie/en/manifest", "r"))
zh_movie_jp_manifest = json.load(open("./zh/movie/jp/manifest", "r"))

def recurse_dir(path):
    repo_req = requests.get(repo + path)
    repo_parser = BeautifulSoup(repo_req.text, 'html.parser')
    table_rows = [row.find_all('a') for row in repo_parser.find_all('table')[0].find_all('tr')[3:-1]]
    directories = [row for row in table_rows if row[0].find_all('img')[0].get('alt') == '[DIR]']
    files = [row for row in table_rows if row[0].find_all('img')[0].get('alt') != '[DIR]']
    if not os.path.exists("./" + path):
        os.mkdir("./" + path)
        print("Creating Directory: " + path)
    for file_row in files:
        file_path = path + file_row[0].get('href')
        file_req = requests.get(repo + file_path)
        if not encrypt:
            if os.path.exists("./" + file_path):
                print("Skipping: " + repo + file_path + " because it already exists...")
            else:
                print("Saving: " + repo + file_path + "...")
                open("./" + file_path, 'wb').write(file_req.content)
        else:
            file_path_split = file_path.split("/")
            isRegularPath = len(file_path_split) < 3
            isJapanSoundOrMovie = len(file_path_split) < 2 and file_path_split[0] == "ja" and file_path_split[1] in ["movie", "sound"]
            isManifest = file_path_split[-1].lower() == "manifest"
            if (not isRegularPath and not isJapanSoundOrMovie) or isManifest:
                continue
            manifest_path_split = []
            root_path_split = []
            if isRegularPath:
                manifest_path_split = file_path[3:]
                root_path_split = file_path[:3]
            if isJapanSoundOrMovie:
                manifest_path_split = file_path[2:]
                root_path_split = file_path[:2]
            manifest_entry = []
            if file_path_split[0] == "en":
                if file_path_split[1] == "asset":
                    if file_path_split[2] == "android":
                        manifest_entry = [resource for resource in en_asset_android_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "ios":
                        manifest_entry = [resource for resource in en_asset_ios_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "movie":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in en_movie_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in en_movie_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "sound":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in en_sound_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in en_sound_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
            if file_path_split[0] == "ja":
                if file_path_split[1] == "asset":
                    if file_path_split[2] == "android":
                        manifest_entry = [resource for resource in jp_asset_android_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "ios":
                        manifest_entry = [resource for resource in jp_asset_ios_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "movie":
                    manifest_entry = [resource for resource in jp_movie_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "sound":
                    manifest_entry = [resource for resource in jp_sound_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
            if file_path_split[0] == "ko":
                if file_path_split[1] == "asset":
                    if file_path_split[2] == "android":
                        manifest_entry = [resource for resource in ko_asset_android_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "ios":
                        manifest_entry = [resource for resource in ko_asset_ios_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "movie":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in ko_movie_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in ko_movie_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "sound":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in ko_sound_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in ko_sound_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
            if file_path_split[0] == "zh":
                if file_path_split[1] == "asset":
                    if file_path_split[2] == "android":
                        manifest_entry = [resource for resource in zh_asset_android_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "ios":
                        manifest_entry = [resource for resource in zh_asset_ios_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "movie":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in zh_movie_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in zh_movie_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                if file_path_split[1] == "sound":
                    if file_path_split[2] == "en":
                        manifest_entry = [resource for resource in zh_sound_en_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
                    if file_path_split[2] == "jp":
                        manifest_entry = [resource for resource in zh_sound_jp_manifest["resources"] if resource["name"] == manifest_path_split.join("\\")]
            if manifest_entry is not None:
                if len(manifest_entry) > 0:
                    encrypted_data = encrypt_xor(file_req.content)
                    open("./" + root_path_split.join("/") + "/" + manifest_entry[0]["hash"], "wb").write(encrypted_data)
                    print("Saving: " + file_path + " as " + manifest_entry[0]["hash"] + "...")

    for dir_row in directories:
        inner_path = path + dir_row[0].get('href')
        recurse_dir(inner_path)
        if not encrypt:
            if not os.path.exists("./" + inner_path):
                print("Creating Directory: " + inner_path)
                os.mkdir("./" + inner_path)
recurse_dir('')