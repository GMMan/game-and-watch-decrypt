Game & Watch Encryption Utility
===============================

This program allows you to import and export data to and from your Game & Watch:
Super Mario Bros. external flash dump. This program supports the main data
region encrypted via OTFDEC and also both NVRAM regions encrypted using
AES-GCM.

Configuration
-------------

First, you must create your config file. Please use `keyinfo.sample.json` as
a template, filling in the keys and IVs with actual values for the Game & Watch.
Save this file as `keyinfo.json` in the executable's directory.

The keys may be found in the following offsets in the Game & Watch's memory:
- OTFDEC
  - Key: 0x080106f4
  - Nonce: 0x0801106e4
- AES-GCM
  - Key: 0x200011c8
  - IV: 0x200011d8

Note that the program expects the keys as arrays of uints, as is how the keys
are supplied to the HAL inside the firmware. If you are reading the values
as bytes, make sure to convert each uint's endian.

Usage
-----

There are two operations, `import` and `export`. `import` encrypts and writes
data to the flash dump, while `export` decrypts and writes data as separate
files. They both take the following options:

```
-c|--config <key-file>     Path to key file
-d|--data <data-file>      Path to main data
-n1|--nvram1 <nvram-file>  Path to first NVRAM copy
-n2|--nvram2 <nvram-file>  Path to second NVRAM copy
```

Supply `-c` if you want to point to a different `keyinfo.json`. The other
options can be supplied if you are interested in importing or exporting their
respective files.

For example, to dump main data, you could run the following:
```
GameAndWatchDecrypt export -d main_data.bin spi_flash_dump.bin
```
where `spi_flash_dump.bin` is the path to where your flash dump is.

To build a new image, you could run the following:
```
GameAndWatchDecrypt import -d main_data.bin -n1 nvram1.bin -n2 nvram2.bin new_image.bin
```

Using as standalone encryptor
-----------------------------

You may use this program as a standalone encryptor for your own STM32
application. You may omit either OTFDEC or AES-GCM params. Just set your offsets
and keys accordingly, and the program will take care of properly encrypting the
data.
