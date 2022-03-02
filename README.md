
# jinventory

*jinventory* uses libudev to gather information from SYSFS about network, CPU, storage devices/hosts 
and present it in JSON format on *stdout*.

Source:
-------
https://github.com/IBM/jinventory

Mailing list:
-------------
jentenma@us.ibm.com
roger@us.ibm.com
rpstewar@us.ibm.com

License:
--------
See 'LICENSE' file.

Compilation dependencies:
-------------------------
- C and C++ compiler (gcc, g++)
- GNU build tools (automake, autoconf, libtool, etc)
- yum: libudev-devel Debian: libudev-dev
- yum: json-c-devel Debian: libjson0 libjson0-dev

Binary dependencies:
-------------
  libudev & json-c .so 

Building:
---------
```
$ ./configure
$ make
$ make install
```
The binary "*jinventory*" will be installed to `/usr/local/bin`

Examples:

    [root@host:~]$ jinventory storage
    { "drive00": { "info": { "path": "pci-0000:1b:00.0-scsi-0:2:0:0", "device": "\/dev\/sda", "vendor": "IBM", "model": "ServeRAID_M5110", "revision": "3.19", "snum": "3600605b0051b04b01b46d280226fbbce", "size": "11718746112", "scsi_generic": "sg0" } } }

    [root@host:~]$ jinventory storage | python -m json.tool
    {
        "drive00": {
            "info": {
                "device": "/dev/sda",
                "model": "ServeRAID_M5110",
                "path": "pci-0000:1b:00.0-scsi-0:2:0:0",
                "revision": "3.19",
                "scsi_generic": "sg0",
                "size": "11718746112",
                "snum": "3600605b0051b04b01b46d280226fbbce",
                "vendor": "IBM"
            }
        }
    }

Building RPMs:
--------------
To build a tarball to feed to rpmbuild, do

    $ make dist-gzip

As an example, use a command similar to the following:

    $ rpmbuild -ba [--target=ppc64le] <path-to-spec-file>

Hacking:
--------
All patches should be sent to the mailing list with linux-kernel style 'Signed-Off-By'. 
The following git commands can be used:
```
- git commit -s
- git format-patch
```
You probably want to read the linux Documentation/Submitting Patches as
much of it applies to jinventory

Submitting patches:
-----------------

  Subject: [jinventory] Summary

--
