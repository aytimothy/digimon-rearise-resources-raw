# digimon-rearise-resources-raw

This repository contains starter code to build out a resource respository for Digimon ReArise.

It is available in:

  * English
  * Japanese
  * Korean
  * Chinese

If you want to download the assets, Chortos has stored a repository of the files [on his website](https://chortos.selfip.net/~astiob/digimon-rearise-resources)... Though you probably want [this](https://mega.nz/folder/jZJyTTaD#SlQNBPp_5Z1KTyWIcHf3hA/folder/2cQBAI4D) version instead which has been pre-processed.

## How to use?

There are two main scripts:

  * `download-raw.py` - Downloads game asset data from the Official Servers (though that has been shut down since).
  * `download-repo.py` - Downloads game asset data from Chortos' store

They both write data to this folder. As you've already noticed, the manifest is already provided as we *can't* store the whole shebang on GitHub.

### download-raw

    python download-raw.py [--global <en/ko/zh>]

Run `download-raw.py` on its own to download from the Japanese server.  
Run `download.raw.py` with the `--global <lang>` option to download from the global servers.

### download-repo

    python download-repo.py [--encrypt/--no-encrypt]

Run `download-repo.py` on its own or with the `--no-encrypt` option to download all the files as-is from Chortos' server (`repo` variable).  
Run `download-repo.py` with the `--encrypt` option to encrypt them for serving to the original game client.

The script will download them all into the repository in its respective folders.

## How to asset?

Just use [Perfare/AssetStudio](https://github.com/Perfare/AssetStudio) and "open folder".  
It might crash/hang due to the sheer amount of assets, but be patient.