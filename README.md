# Burp-Decryption-Handler

Decrypt the AES key in response using RSA key and also leverage the AES key to decrypt data.

### Build
Brew install gradle
gradle build
Artifact inside /build/libs

### setup
Define the private key in system environment

#### Linux/MacOS
`vim ~/.zshrc`
```
export private_key_path="/tmp/key.pri"
```
`source ~/.zshrc`

#### Windows
`setx private_key_path "/tmp/key.pri"`