# deflate-frolicking

Analyse and modify DEFLATE streams.

For more context, check the accompanying [article](https://nevesnunes.github.io/blog/2021/09/29/Decompression-Meddlings.html).

## Build

```sh
pip install -r requirements.txt
git submodule update --init --recursive
(cd ./vendor/infgen/ && gcc infgen.c -o infgen)
(cd ./vendor/tree-sitter-json/ && make)

export PATH=$PWD/vendor/infgen:$PATH
```

## Scripts

- `./fix_deflate_w_sitter.py` - Detects decompression error offsets and generates candidate bytes to replace at those offsets, allowing the user to interactively select the best candidate.
- `./embellish.py` - Adds a dummy block with arbitrary bytes in the dynamic huffman table, without affecting decompression output.

## Examples

### Fix a compressed JSON file

Consider the following byte change:

```diff
diff -au <(xxd 000_samples/CVE-2011-4925.deflate) <(xxd 110_dist_too_far_back/CVE-2011-4925.deflate)
--- 000_samples/CVE-2011-4925.deflate
+++ 110_dist_too_far_back/CVE-2011-4925.deflate
@@ -3,7 +3,7 @@
 00000020: 34d8 1332 5ae3 7167 c6a4 5195 ffbe 776c  4..2Z.qg..Q...wl
 00000030: 70ec 280d b4ea 2e57 2112 9e7b 7de7 dc0f  p.(....W!..{}...
 00000040: 9f33 919c 6f47 8458 9148 6ff9 3297 5473  .3..oG.X.Ho.2.Ts
-00000050: 912a 2b20 df60 15d6 fbd7 839b 986a 7ab3  .*+ .`.......jz.
+00000050: 912a 2b20 df40 15d6 fbd7 839b 986a 7ab3  .*+ .@.......jz.
 00000060: 6652 8109 2c96 d7ee 58c7 a539 1531 33de  fR..,...X..9.13.
 00000070: 9f8b 4bb2 b9ab 3045 19bb 5951 1ddd d5cc  ..K...0E..YQ....
 00000080: 4d97 ad9b dbbd 92dc 0486 ef81 dbee 0634  M..............4
```

Which causes decompression to fail:

```sh
python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' 110_dist_too_far_back/CVE-2011-4925.deflate
# Traceback (most recent call last):
#   File "<string>", line 1, in <module>
# zlib.error: Error -3 while decompressing data: invalid distance too far back
```

Now let's generate candidate fixes:

```sh
./fix_deflate_w_sitter.py 110_dist_too_far_back/CVE-2011-4925.deflate
```

After picking the 8th candidate, which seems to produce the longest valid output, the following files are written to the local directory:

```sh
./@0x54_0xdf_0x60.out  # Decompressed output
./@0x54_0xdf_0x60.fix  # Fixed stream
```

To confirm this candidate matches the original uncompressed JSON file:

```sh
diff -au \
   000_samples/CVE-2011-4925.deflate \
   @0x54_0xdf_0x60.fix \
   | wc -c
# 0 (no bytes are different)
````

### Add a plaintext message to a DEFLATE stream

**TODO**: Fix some cases that either throw errors during concatenation or result in an invalid stream.

```bash
./embellish.py 000_samples/CVE-2011-4925.deflate 'hello world!'
```

To ensure the added block doesn't affect decompression output:

```bash
diff -au \
    <(python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' 000_samples/CVE-2011-4925.deflate) \
    <(python3 -c 'import sys,zlib;print(zlib.decompress(open(sys.argv[1], "rb").read(), -15))' 200_hello/CVE-2011-4925.deflate.embellished) \
    | wc -c
# 0 (no bytes are different)
```

To read the message:

```diff
diff -au <(xxd 000_samples/CVE-2011-4925.deflate) <(xxd 200_hello/CVE-2011-4925.deflate.embellished)
--- 000_samples/CVE-2011-4925.deflate
+++ 200_hello/CVE-2011-4925.deflate.embellished
@@ -1,85 +1,88 @@
-00000000: cd5b 5d6f da48 147d cfaf 1879 5f76 ab80  .[]o.H.}...y_v..
-00000010: b1b1 d3c4 4f4b 095b 591b 2005 924a ad50  ....OK.[Y. ..J.P
-00000020: 34d8 1332 5ae3 7167 c6a4 5195 ffbe 776c  4..2Z.qg..Q...wl
-00000030: 70ec 280d b4ea 2e57 2112 9e7b 7de7 dc0f  p.(....W!..{}...
-00000040: 9f33 919c 6f47 8458 9148 6ff9 3297 5473  .3..oG.X.Ho.2.Ts
 [...]
+00000000: 2c4b 5d6f da48 147d cfaf 1879 5f76 ab80  ,K]o.H.}...y_v..
+00000010: b1b1 d3c4 4f4b 095b 591b 2068 656c 6c6f  ....OK.[Y. hello
+00000020: 2077 6f72 6c64 2167 c6a4 5195 ffbe 776c   world!g..Q...wl
+00000030: 7ace 39e7 9c3b 0669 deea 7ad3 46a2 e87b  z.9..;.i..z.F..{
+00000040: 7ec5 c8fb b25b 058c 8d9d 267e 5a4a d8ca  ~....[....&~ZJ..
 [...]
```

