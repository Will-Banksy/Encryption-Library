# Encryption Library (EncLib)

A simple wrapper to various encryption algorithms, currently just AES-128, accessed through the AESEncryption::AES128 static method

## Compiling

### Shared Library

Simply run cmake and make (or ninja or whatever you want to use)

First make a build directory in the project root directory and enter that, then:

```bash
cmake ..
make
```

### Static Library

Simply run cmake (but setting the option ENCLIB_STATIC to ON) and make (or ninja or whatever you want to use)

First make a build directory in the project root directory and enter that, then:

```bash
cmake -DENCLIB_STATIC=ON ..
make
```