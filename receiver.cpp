#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <streambuf>
#include <string>

using namespace std;
const string pubKeyName = "publicKey.txt";
const string privKeyName = "privateKey.txt";
// reads the key from the file
char *readKey(string fileName)
{
    ifstream file(fileName.c_str());
    string contents((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    char *key = (char *)malloc(strlen(contents.c_str()) * sizeof(char) + 1);
    strcpy(key, (char *)contents.c_str());
    file.close();
    return key;
}

//helper function to convert private key in string format to RSA format
RSA *convertPrivateKeyToRSA(FILE *fp, int length)
{
    RSA *p_key = NULL;
    RSA *x = PEM_read_RSAPrivateKey(fp, &p_key, NULL, NULL);
    return p_key;
}

//helper function to convert public key in string format to RSA format
RSA *convertPublicKeyToRSA(FILE *fp, int length)
{
    RSA *publicKey = NULL;
    RSA *temp = PEM_read_RSA_PUBKEY(fp, &publicKey, NULL, NULL);
    return publicKey;
}

int main()
{
    // 1. Read the keys
    string publicKey = readKey(pubKeyName);
    string privateKey = readKey(privKeyName);
    //2. Display the keys
    cout << "Public key of receiver:" << '\n'
         << publicKey << '\n'
         << "Private key of receiver:\n"
         << privateKey << '\n';
    string input;
    // 3. Open the named pipe in write only mode
    fstream pipe;
    pipe.open("pipeEx9", ios::out);
    // 4. Write the public key to the pipe and close the pipe
    pipe << publicKey;
    pipe.close();
    // 5. Convert the public key in string format to RSA format
    FILE *pubKeyFd = fopen64(pubKeyName.c_str(), "r");
    FILE *privKeyFd = fopen64(privKeyName.c_str(), "r");
    RSA *publicKeyRSA = convertPublicKeyToRSA(pubKeyFd, publicKey.length());
    RSA *privateKeyRSA = convertPrivateKeyToRSA(privKeyFd, privateKey.length());
    // 6. Open the pipe again in read only mode
    pipe.open("pipeEx9", ios::in);
    // 7. Read the incoming message length and the incoming message

    stringstream ss;
    ss << pipe.rdbuf();
    string incomingMessage = ss.str();
    // 8. Close the pipe
    pipe.close();
    // 9. Display the received encrypted message
    cout << "Encrypted message:\n"
         << incomingMessage << '\n';
    size_t mesLen = incomingMessage.length() + 1;
    // 10. Decrypt the message
    unsigned char *msg = new unsigned char[mesLen];
    incomingMessage.copy((char *)msg, mesLen);
    unsigned char *decrypted = new unsigned char[220];
    fill(decrypted, decrypted + 220, 0);
    int ret = RSA_private_decrypt(mesLen, msg, decrypted, privateKeyRSA, RSA_PKCS1_OAEP_PADDING);
    // 11. Display the decrypted message
    cout << "result: " << ret << endl;
    if (ret == -1) {
        bool repeat = false;
        do {
            auto err = ERR_get_error();
            if (err) {
                char err_buf[256];
                ERR_error_string(err, err_buf);
                cout << err_buf << endl;
            }
            repeat = err;
        } while (repeat);
    }
    cout << "Decrypted message: " << decrypted << '\n';
    // 12. Free memory used
    RSA_free(publicKeyRSA);
    fclose(pubKeyFd);
    return 0;
}
