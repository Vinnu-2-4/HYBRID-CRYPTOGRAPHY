# HYBRID-CRYPTOGRAPHY
In this Project we will see the working of Hybrid Cryptography in securing a File. 
Here I'm using 2 cryptographic algorithms,they are
Symmetric Algo -- AES
Asymmetric Algo -- RSA


HYBRIDCRYPTOSYSTEDESIGN
 
The device has been configured to function as follows:
1.First the user is given a menu with three options.
2.The three options contain different tasks of their own.
3.In the first option the user directly enters the message which should be encrypted in the output.
4.In option 2 the user imports the file which should be encrypted from his local disk.
5.The final option contains an exit that terminates the program.

In the first two options the encryption and decryption are performed as shown below:
1. First RSA public and private keys are generated.
2. Next AES symmetric key is generated.
3. The next step is to encrypt the data generated by the user through the symmetrical key of the AES and to display the created cipher text.
4. The symmetric AES key is encrypted by means of a public RSA key.
5.The ciphertext and the private key and the AES symmetric key encrypted are sent by the sender now.
6.Ciphertext, a private key, and a symmetrical AES key received by the receivers.
First the recipient uses his private key to uncode the symmetric AES key, then the recipient decrypts the encrypted message by using the symmetric AES key.

HOW TO RUN:
1. Use pycharm
2. Required packages are
    - Cryptography
    - pip
    - pycparser
    - pycryptodome
    - pycryptodomex
    - cffi
3. Run the Hybrid.py 
