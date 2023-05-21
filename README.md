# AESculap

Implementation of the Advanced Encryption Standard (AES) algorithm.

`aesculap` is just a little hobbyist project for learning purposes.

The binary provides a little CLI tool to encrypt/decrypt files.
The library is not intended to be used in external code.

## CLI usage

``` console
$ aesculap encrypt --help
Usage: aesculap encrypt [OPTIONS] --key-file <KEY_FILE> <--cbc|--ecb> <--input-file <INPUT_FILE>|--stdin> <--output-file <OUTPUT_FILE>|--stdout>

Options:
  -k, --key-file <KEY_FILE>
          The key must have a size of 128, 192 or 256 bits (16, 24 or 32 bytes)

      --cbc
          Cipher Block Chaining mode

          An initialization vector (IV) is used and the blocks are chained together. It is generally more secure.

      --ecb
          Electronic Code Book mode (not recommended)

          Each block is encrypted with the same key and algorithm. It is fast and easy but quite insecure.

  -p, --padding <PADDING>
          Padding is required to divide the data into even sized blocks

          [default: pkcs7]

          Possible values:
          - pkcs7: Padding is done according to PKCS #7 (recommended)
          - zero:  The blocks are filled with zeroes
          - none:  The data is not padded (may fail)

      --iv-file <IV_FILE>
          In CBC mode an IV with a size of 128 bits (16 bytes) is required

      --random-iv <IV_FILE>
          Generate a random IV and write it to a file

  -i, --input-file <INPUT_FILE>
          Read the input from a file

      --stdin
          Read the input from STDIN

  -o, --output-file <OUTPUT_FILE>
          Write the output to a file

      --stdout
          Write the output to STDOUT

  -h, --help
          Print help (see a summary with '-h')

$ aesculap decrypt --help
Usage: aesculap decrypt [OPTIONS] --key-file <KEY_FILE> <--cbc|--ecb> <--input-file <INPUT_FILE>|--stdin> <--output-file <OUTPUT_FILE>|--stdout>

Options:
  -k, --key-file <KEY_FILE>
          The key must have a size of 128, 192 or 256 bits (16, 24 or 32 bytes)

      --cbc
          Cipher Block Chaining mode

          An initialization vector (IV) is used and the blocks are chained together. It is generally more secure.

      --ecb
          Electronic Code Book mode (not recommended)

          Each block is encrypted with the same key and algorithm. It is fast and easy but quite insecure.

  -p, --padding <PADDING>
          [default: pkcs7]

          Possible values:
          - pkcs7: Padding is done according to PKCS #7 (recommended)
          - zero:  The blocks are filled with zeroes
          - none:  The data is not padded (may fail)

      --iv-file <IV_FILE>
          In CBC mode an IV with a size of 128 bits (16 bytes) is required

  -i, --input-file <INPUT_FILE>
          Read the input from a file

      --stdin
          Read the input from STDIN

  -o, --output-file <OUTPUT_FILE>
          Write the output to a file

      --stdout
          Write the output to STDOUT

  -h, --help
          Print help (see a summary with '-h')
```

## Sources
- [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [tutorialspoint.com](https://www.tutorialspoint.com/cryptography/advanced_encryption_standard.htm)
- [Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box)
- [AES key schedule](https://en.wikipedia.org/wiki/AES_key_schedule)
- [Rijndael MixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns)
- [braincoke.fr on the AES Key Schedule](https://braincoke.fr/blog/2020/08/the-aes-key-schedule-explained/)
- [AES encryption and decryption tool](https://devtoolcafe.com/tools/aes)
- [PKCS padding](https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
- [test vectors](https://www.cryptool.org/en/cto/aes-step-by-step)
