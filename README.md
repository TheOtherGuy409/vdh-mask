# vdh-mask

## What is it ?

Starting at version 5.6.0 for the Firefox version, the [Video DownloadHelper](https://addons.mozilla.org/firefox/addon/video-downloadhelper/) extension supports the *masked download* operation, which allows a file to be downloaded without touching the local disk in clear form. 

***vdh-mask*** is a command-line utility to decrypt DownloadHelper-generated files to be viewed by any regular video player.

In addition, ***vdh-mask*** allows encrypting files with the same specifications as DownloadHelper.

## How does it work ?

When encrypting a file, 2 new files are created:

* ***xyz.bin*** is the original file, encrypted according to Video DownloadHelper standards
* ***xyz.vdh*** is a JSON file containing the fields:
  * ***biniv***: the *base64* representation of the initial value when encrypting *xyz.bin*
  * ***metaiv***: the *base64* representation of the initial value when encrypting field *meta*
  * ***meta***: the *base64* representation of an encrypted JSON object containing the meta-data for the file. In particular, this object has a field *originalFilename* which represents the initial file name of file *xyz.bin*
  
Both the file *xyz.bin* and the value of field *meta* in file *xyz.vdh* are encrypted using the same key. This key is the SHA-256 hash code of the password that can be passed as an argument to *vdh-mask* but has a default value (the same in *vdh-mask* and Video DownloadHelper). The encryption is performed using the AES-CTR 256 algorithm.

Note that for the *.vdh* and *.bin* files to be associated, they must share the same basename, in the examples above *xyz*. 

Keeping the default password (hence the default key) might be sufficient for the level of privacy you need, but if you want a high level of protection, you should use your own password when encrypting and decrypting a file.

## How to use vdh-mask ?

The general usage syntax is:
```
node vdh-mask.js [options] <input file>
```

By default, if *&lt;input file>* ends with *.vdh*, the operation will be a decryption, otherwise, the input file will be encrypted.

Available options are:
```
    -h, --help                    output usage information
    -V, --version                 output the version number
    -f, --force                   Overwrite output files
    -p, --password <password>     Password
    -o, --output <output file>    Output file base name
    -d, --decode                  Force decode
    -e, --encode                  Force encode
    -b, --blocksize <block-size>  Block size
```


