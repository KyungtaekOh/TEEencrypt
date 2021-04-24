# OPTEE-Encryption

### File Encryption (Caesar & RSA)

#### Caesar code
Read a file to encrypt it and save it in file form again.</br>

#### Execution statement</br>
-Enc : TEEencrypt -e [filename] [algorithm]</br>
-Dec(Caesar) : TEEencrypt -d [filename] [key_filename] [alogorithm]</br>
-Dec(RSA) : this version only has encryption capabilities.
</br>

#### RSA Reference
Used the code of https://github.com/cezane/optee_rsa_example
