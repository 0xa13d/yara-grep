## ygrep

CLI tool for rapid Yara rule prototyping.

## Installation

`pip install yara-grep`

## Usage

```
usage: ygrep.py [-h] [-l] [-n] [-a] [-m MODIFIER] [-b BYTES] [-s STRING] [path]

yara grep - cmdline string/byte search

positional arguments:
  path                  search path (default: **)

optional arguments:
  -h, --help            show this help message and exit
  -l, --quiet           list matching filenames only (suppress normal output)
  -n, --dry-run         do not scan, compile rule only
  -a, --any             set condition to 'any of them' (default: 'all of them')
  -m MODIFIER, --modifier MODIFIER
                        modifier for string patterns - e.g. ascii,wide,nocase,xor,base64,base64wide
  -b BYTES, --bytes BYTES
                        bytes to grep
  -s STRING, --string STRING
                        string to grep
```

## Example

```
>>> ygrep -s "InternetConnectA" -s "WinHttpConnect" -a -m "xor"
rule x {
    strings:
        $s0 = "InternetConnectA" xor
        $s1 = "WinHttpConnect" xor
    condition:
        any of them
}

extracted\api.VirtualAlloc.0x504000.mem
--------  -------------------  -----------------------------------------------
0x229d5c  b'InternetConnectA'  49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41
0x22ab1a  b'WinHttpConnect'    57 69 6e 48 74 74 70 43 6f 6e 6e 65 63 74
--------  -------------------  -----------------------------------------------
extracted\api.VirtualAlloc.0x85000.mem
-------  -------------------  -----------------------------------------------
0x28dcc  b'InternetConnectA'  49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41
-------  -------------------  -----------------------------------------------
sdfmsdofpd
---  ----------------------------  -----------------------------------------------
0x8  b"\x1c;!0';0!\x16:;;06!\x14"  1c 3b 21 30 27 3b 30 21 16 3a 3b 3b 30 36 21 14
---  ----------------------------  -----------------------------------------------

>>> ygrep -b "AA ?? AA ?? BB" -s "kernel32"

rule x {
    strings:
        $s0 = "kernel32" ascii wide nocase
        $b0 = { AA ?? AA ?? BB }
    condition:
        all of them
}

samples\tmp7v4jjmpn
---------  -----------------------  -----------------------
0x52f8     b'kernel32'              6b 65 72 6e 65 6c 33 32
0xe554     b'kernel32'              6b 65 72 6e 65 6c 33 32
0x27a08    b'kernel32'              6b 65 72 6e 65 6c 33 32
0x27c46    b'kernel32'              6b 65 72 6e 65 6c 33 32
0x27d34    b'kernel32'              6b 65 72 6e 65 6c 33 32
0x28578    b'kernel32'              6b 65 72 6e 65 6c 33 32
0x5a91c    b'KERNEL32'              4b 45 52 4e 45 4c 33 32
0xa5224    b'KERNEL32'              4b 45 52 4e 45 4c 33 32
0xf50ac    b'KERNEL32'              4b 45 52 4e 45 4c 33 32
0x102a00   b'KERNEL32'              4b 45 52 4e 45 4c 33 32
0x1137bf0  b'\xaa\xb4\xaa\xa3\xbb'  aa b4 aa a3 bb
0x151c6a2  b'\xaa\x7f\xaa\xfe\xbb'  aa 7f aa fe bb
---------  -----------------------  -----------------------
```

