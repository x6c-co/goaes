
# goaes

`goaes` is a very simple tool for encrypting files with AES-256 GCM.

## about

I wanted to write some Go and encryption fascinates me, so I wrote `goaes`.

### what it is

- it's fun
- it's fast
- it's simple

### what it isn't

- it's not meant for production
- it's not meant for sensitive data
- it's not secure

## how it works

- it uses [Argon2id](https://en.wikipedia.org/wiki/Argon2)
	- time: `3`
	- memory: `256mb`
	- threads: `4`
	- key length: `32`
- it uses [key wrapping](https://en.wikipedia.org/wiki/Key_wrap)

## getting started

1. Generate a new passphrase.

```bash
goaes generate
```

Don't use this one. This one is mine.

```
XGfpiNUvKJy8k7KeUEyhev4jkTIajb1s9CMJP9xH/7A=
```

2. Set `GOAES_PASSPHRASE` to the passphrase.
3. Run the `goaes encrypt` command.

```bash
export GOAES_PASSPHRASE=XGfpiNUvKJy8k7KeUEyhev4jkTIajb1s9CMJP9xH/7A=

goaes encrypt ./input.txt
```

```
hexdump -C ./input.txt.goaes

00000000  3e 7f 03 01 01 14 45 6e  63 72 79 70 74 65 64 44  |>.....EncryptedD|
00000010  61 74 61 50 61 79 6c 6f  61 64 01 ff 80 00 01 03  |ataPayload......|
00000020  01 03 44 45 4b 01 0a 00  01 04 53 61 6c 74 01 0a  |..DEK.....Salt..|
00000030  00 01 07 50 61 79 6c 6f  61 64 01 0a 00 00 00 ff  |...Payload......|
00000040  8d ff 80 01 3c b6 8c 2a  3d bb 28 f0 20 1f 45 d2  |....<..*=.(. .E.|
00000050  6b 31 1d ba 6e dc 4b b5  b8 ba 01 52 b7 be e2 84  |k1..n.K....R....|
00000060  c9 25 b5 2c fc 13 c7 49  aa 70 d3 7e ab 78 4c 49  |.%.,...I.p.~.xLI|
00000070  f2 1b 8b 50 1a 06 d3 bf  fc cd 29 73 74 27 05 8c  |...P......)st'..|
00000080  cc 01 20 13 74 7e 13 e7  39 09 9d 93 85 52 59 88  |.. .t~..9....RY.|
00000090  21 9c 31 84 39 65 f7 73  cc 9e 86 3c 82 dd 1e 89  |!.1.9e.s...<....|
000000a0  d3 8b 1a 01 28 36 6d b1  fd 37 85 ba a0 d8 e7 5e  |....(6m..7.....^|
000000b0  93 99 0d 74 a9 d4 b2 04  8a 47 bf 70 61 6a 76 42  |...t.....G.pajvB|
000000c0  13 e6 f0 50 60 74 c4 55  e4 b2 43 69 32 00        |...P't.U..Ci2.|
000000ce
```

### usage

```bash
NAME:
   goaes - Simple AES encryption built with Go

USAGE:
   goaes [global options] [command [command options]]

COMMANDS:
   generate, g  Generate a base64 encoded key
   encrypt, e   Encrypt a file
   decrypt, d   Decrypt a file
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## reference material

- https://en.wikipedia.org/wiki/Key_wrap
- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- https://en.wikipedia.org/wiki/Galois/Counter_Mode
- https://en.wikipedia.org/wiki/Authenticated_encryption
- https://en.wikipedia.org/wiki/Argon2
- https://en.wikipedia.org/wiki/Key_derivation_function
- https://en.wikipedia.org/wiki/Salt_(cryptography)
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://words.filippo.io/2025-state/

## inspiration

- https://github.com/FiloSottile/age
- https://github.com/restic/restic
