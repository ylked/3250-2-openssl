#!/bin/bash 

HOME_DIR=$(pwd)
ALICE_DIR="$HOME_DIR/alice"
BOB_DIR="$HOME_DIR/bob"

PLAIN_SECRET="secret.txt"
ENC_SECRET="secret.txt.enc"
DEC_SECRET="secret.txt.dec"
ENC_SECRET_HASH="secret.txt.enc.hash"
PLAIN_SECRET_HASH="secret.txt.hash"
ENC_SECRET_SIG="secret.txt.enc.sig"
PLAIN_SECRET_SIG="secret.txt.sig"
ALICE_KR="alice.key"
ALICE_KU="alice.key.pub"
BOB_KR="bob.key"
BOB_KU="bob.key.pub"

PLAIN_MESSAGE="message.txt"
ENC_MESSAGE="message.txt.enc"
DEC_MESSAGE="message.txt.dec"

# clear directories before beginning
rm -r $ALICE_DIR/*
rm -r $BOB_DIR/*

# alice generates a key pair
cd $ALICE_DIR
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $ALICE_KR
openssl rsa -pubout -in $ALICE_KR -out $ALICE_KU

echo Alice generated a new key pair
echo Alice private key : 
cat $ALICE_KR

echo 
echo Alice public key 
cat $ALICE_KU

# bob generates a key pair 
cd $BOB_DIR
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $BOB_KR
openssl rsa -pubout -in $BOB_KR -out $BOB_KU

echo Bob generated a new key pair
echo Bob private key : 
cat $BOB_KR

echo 
echo Bob public key 
cat $BOB_KU

# alice and bob exchange their public keys
cp "$BOB_DIR/$BOB_KU" "$ALICE_DIR/$BOB_KU"
cp "$ALICE_DIR/$ALICE_KU" "$BOB_DIR/$ALICE_KU"

echo
echo Alice and Bob exchanged their public keys
echo

# alice creates a password to generate a key
cd $ALICE_DIR

echo Alice creates a random password to generate a key
PASSWORD=$(openssl rand -base64 32)
echo $PASSWORD

# she generates the key
openssl enc -aes-256-ofb -P -k $PASSWORD > $PLAIN_SECRET

echo She generated a new AES key from the password: 
cat $PLAIN_SECRET
echo 

# she gets the parameters from the generated key
ALICE_IV=$(cat $PLAIN_SECRET | grep iv | cut -d '=' -f2)
ALICE_SALT=$(cat $PLAIN_SECRET | grep salt | cut -d '=' -f2)
ALICE_KEY=$(cat $PLAIN_SECRET | grep key | cut -d '=' -f2)

# alice wants to share this secret with bob
# thus, she encrypts the secret with the public key of bob
openssl rsautl -encrypt -inkey $BOB_KU -pubin -in $PLAIN_SECRET -out $ENC_SECRET

echo She encrypted it:
cat $ENC_SECRET
echo

# then signs the message
# an other way to do this would be to first sign the message and then encrypt it.
# First, she needs to find the hash of the message
# she uses SHA-512 algorithm

openssl dgst -out $ENC_SECRET_HASH -sha512 $ENC_SECRET

echo She created a hash for the encrypted secret
cat $ENC_SECRET_HASH
echo

# then, she can sign the secret
openssl dgst -sha512 -sign $ALICE_KR -out $ENC_SECRET_SIG $ENC_SECRET_HASH

echo And she signed the hash
cat $ENC_SECRET_SIG
echo 

# alice sends the encrypted secret and the signature to bob
# in this example, we only copy the file to another directory but
# irl, the file would be transfered on the internet
cp "$ALICE_DIR/$ENC_SECRET" "$BOB_DIR/$ENC_SECRET"
cp "$ALICE_DIR/$ENC_SECRET_SIG" "$BOB_DIR/$ENC_SECRET_SIG"

echo She sends Bob the encrypted secret and the signature

# now bob must first verify the signature
cd $BOB_DIR
# he hashes the message
openssl dgst -sha512 $ENC_SECRET > $ENC_SECRET_HASH

echo Bob creates a hash for the encrypted secret

# and finally, he can verify the signature
openssl dgst -sha512 -verify $ALICE_KU -signature $ENC_SECRET_SIG $ENC_SECRET_HASH

echo And he verifies the signature validity

if [[ $? -ne 0 ]]; then
  echo "Signature verification failed, stopping now"
  exit 1
fi

echo 

# if verification succeeded, bob can decrypt the message
openssl rsautl -decrypt -inkey $BOB_KR -in $ENC_SECRET -out $DEC_SECRET

echo He then decrypts the secret using his private key:
cat $DEC_SECRET
echo 

# assertion : the secret decrypted by Bob must be the same as the plain secret created by alice
# this cannot be verified in real life conditions, we do it only for debug purposes
if [[ $(cat "$ALICE_DIR/$PLAIN_SECRET") != $(cat "$BOB_DIR/$DEC_SECRET") ]]; then
  echo "decrypted secret is not the same as the plain one, stopping now"
  exit 2
fi

# he can now get the IV, the key and the salt from the file
BOB_IV=$(cat $DEC_SECRET | grep iv | cut -d '=' -f2)
BOB_SALT=$(cat $DEC_SECRET | grep salt | cut -d '=' -f2)
BOB_KEY=$(cat $DEC_SECRET | grep key | cut -d '=' -f2)

# now alice and bob have everything they need to communicate using a symmetric key
# for example, bob wants to send a message to alice
# he first write it in a plain file

cat > $PLAIN_MESSAGE << EOF 
Hello Alice, 
I hope everything is going well for you. 
Best regards,
Bob
EOF

echo He can now write a message to Alice

# bob encrypts the message
openssl enc -aes-256-ofb -S $BOB_SALT -K $BOB_KEY -iv $BOB_IV -in $PLAIN_MESSAGE -out $ENC_MESSAGE

echo And he encrypts it using the AES key he just received
cat $ENC_MESSAGE
echo

# he sends it to alice
cp "$BOB_DIR/$ENC_MESSAGE" "$ALICE_DIR/$ENC_MESSAGE"

echo He sent the encrypted message to Alice
echo

cd $ALICE_DIR

# alice now decrypts the message
openssl enc -d -aes-256-ofb -S $ALICE_SALT -K $ALICE_KEY -iv $ALICE_IV -in $ENC_MESSAGE -out $DEC_MESSAGE

echo
echo Alice has now decrypted the message

echo "alice received the message :"
cat $DEC_MESSAGE

