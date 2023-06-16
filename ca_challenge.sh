#!/usr/bin/env bash

app::main() {
    # The CA needs:
    #  1) The EK public key to encrypt the challenge to (or, better, the EK cert to extract the key from to use?)
    #  2) The AK public key blob, which includes content such as the key attributes
    #  3) The AK name, which is a hash of the public key blob

    # Get manufacturer CA certs
    wget -O - -q https://www.infineon.com/dgdl/Infineon-TPM_RSA_Root_CA-C-v01_00-EN.cer?fileId=5546d46253f6505701540496a5641d20 \
        | openssl x509 -out Infineon-RSA-Root.pem
    wget -O - -q https://pki.infineon.com/OptigaRsaMfrCA036/OptigaRsaMfrCA036.crt \
        | openssl x509 -out Infineon-RSA-Int.pem

    # Confirm validity of the user's EK cert
    openssl verify \
        -verbose \
        -CAfile <( cat Infineon-RSA-Root.pem Infineon-RSA-Int.pem ) \
        RSA_EK_cert.bin

    # Extract public key from user's EK cert
    openssl x509 -inform der -in RSA_EK_cert.bin -pubkey -noout > RSA_EK_pub.pem
    openssl x509 -inform der -in RSA_EK_cert.bin -pubkey -noout | openssl enc -base64 -d > RSA_EK_pub.der
}

app::main "$@"
