# deflate-frolicking

Analyse and modify DEFLATE streams.

For more context, check the accompanying [article](https://nevesnunes.github.io/blog/2021/09/29/Decompression-Meddlings.html).

## Scripts

- `./fix_deflate_w_sitter.py` - Detects decompression error offsets and generates candidate bytes to replace at those offsets, allowing the user to interactively select the best candidate.
- `./embellish.py` - Adds a dummy block with arbitrary bytes without affecting decompression output.

## Usage

Add a plaintext message to a DEFLATE stream:

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
