# SHA-256-ARM-64-bit-assembly

Implementation of the FIPS 180-4  SHA-256 algorithm in ARM 64-bit assembly language    https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

For better readability of the source code:

Aliases are used for all registers -> see file 'aliases'

Macros encapsulate frequently recurring commands and boilerplate for function declaration, functions for preprocessing (padding), sha-functions, message parsing, and hash computation  -> see file 'macro.sx'

C-interface for the public function in sha256.sx -> sha256.h

Unit tests: see sha256tests.c and sha256tests.h

Developed on a RaspberryPi 4 (Broadcom BCM2711, Quad core Cortex-A72 (ARM v8) 64-bit SoC @ 1.5GHz) with Raspberry Pi OS
