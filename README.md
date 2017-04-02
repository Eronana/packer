# packer
This is a packer for exe under win32.

You can use it to pack any 32-bit exe file.

## Build
**Please use `Microsoft Visual Studio Community 2015` to build this project.**
1. Open `packer.sln` by VS
2. Build

## Compressor
This project use [compressor](https://github.com/Eronana/compressor) to compress data to reduce exe file iexe

## Usage
Just run `packer a.exe`.

`a.exe` is the file you want to pack.

This is detail usage from `packer.exe`:
```
Usage: packer a.exe [options]
Options:
  -level: compression level. 0 for store, 9 for highest
          compression ratio. default is 3.
  -lazy : set max lazy match, default is 8.
  -chain: set max length of find in hash chain, default is 32.

Notice: lazy and chain will be ignored if you setted level.
```
