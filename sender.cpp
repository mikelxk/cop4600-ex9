#include <fstream>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <stdio.h>
#include <string.h>

using namespace std;

//helper function to convert public key in string format to RSA format
RSA *convertPublicKeyToRSA(FILE *fp, int length)
{
    RSA *r = NULL;
    RSA *x = PEM_read_RSA_PUBKEY(fp, &r, NULL, NULL);
    return r;
}

int main()
{
    fstream pipe;
    // 1. Open the named pipe in read only mode
    pipe.open("pipeEx9", ios::in);
    // 2. Read the public key of the receiver from the pipe
    stringstream ss;
    ss << pipe.rdbuf();
    string pubKey = ss.str();
    // 3. Close the pipe
    pipe.close();
    // 4. Display the received public key
    cout << "Public key of receiver:\n"
         << pubKey << '\n';
    // 5. Input a message from the user using standard input
    string message;
    cout << "Enter the message:\n";
    cin >> message;
    // 6. Convert the public key of the receiver from string in to RSA strucure format
    size_t mesLen = message.length() + 1;
    unsigned char *msg = new unsigned char[mesLen];
    message.copy((char *)msg, mesLen);
    FILE *fp = fopen64("publicKey.txt", "r");;
    RSA *rsa = convertPublicKeyToRSA(fp, pubKey.length());
    unsigned char *encryptedMessage = new unsigned char[RSA_size(rsa)];
    fill(encryptedMessage, encryptedMessage + RSA_size(rsa), 0);
    // 7. Encrypt the message using the RSA public encryption API
    int ret = RSA_public_encrypt(mesLen, msg, encryptedMessage, rsa, RSA_PKCS1_OAEP_PADDING);
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
    // 8. Display the encrypted message
    cout << "Encrypted message:\n"
         << encryptedMessage << '\n';
    // 9. Open the named pipe in write only mode
    pipe.open("pipeEx9", ios::out);
    // 10. Write the encrypted message to the pipe
    pipe << encryptedMessage;
    // 11. Close the pipe
    pipe.close();
    // 12. Free memory used.
    RSA_free(rsa);
    fclose(fp);
}
