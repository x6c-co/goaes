# goaes

`goaes` is a very simple tool for encrypting files with AES-256 GCM.

## about

I wanted to write some Go and encryption fascinates me, so I wrote `goaes`.

### what it is

- it's a fun project
- it uses [key wrapping](https://en.wikipedia.org/wiki/Key_wrap)
- it's fast
- it's simple

### what it isn't

- it's not meant for production
- it's not meant for sensitive data
- it's not secure

## getting started

1. Generate a new main key.

```bash
goaes generate
```

Don't use this one. This one is mine.

```bash
XGfpiNUvKJy8k7KeUEyhev4jkTIajb1s9CMJP9xH/7A=
```

2. Set `SECRET_KEY` to the value of the key you generated.
3. Run the `goaes` command.

```bash
SECRET_KEY=XGfpiNUvKJy8k7KeUEyhev4jkTIajb1s9CMJP9xH/7A= goaes encrypt -s ./input.txt -d ./output.enc
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
