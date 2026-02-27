# TorComm
Secure P2P communication application using Crypto++ ECC and Tor

![GUI](../symbols/"gui_image.png")

packages: jsoncpp, cURL, Boost, Crypto++

install in Debian with
```
sudo apt-get install libjsoncpp-dev libcurl4-openssl-dev libboost-all-dev libcrypto++-dev
```

install in Macos with
```
brew install boost curl jsoncpp cryptopp
```


For cryptography, the hkdf salt defined in message.h (namespace Cryptography) is:
0x8f, 0x49, 0xa8, 0x2c, 0x21, 0xb5, 0x96, 0x5c
