import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Person:
    RSA_KEY_SIZE = 2048
    RSA_KEY_EXPONENT = 65537
    HASH_ALGORITHM = hashes.SHA512()
    AES_KEY_SIZE_BITS = 256

    def __init__(self, name):
        """
        Creates a new person and generates their RSA key pair
        :param name: the name of the person
        """
        self.name = name
        self.key = self._generate_rsa_key_pair()
        self.public_keys_directory: dict[str, rsa.RSAPublicKey] = {}

        self.aes_key = None

    @classmethod
    def _generate_rsa_key_pair(cls):
        """
        Generates a new RSA key pair
        :return rsa.RSAPublicKey: The generated private key
        """
        return rsa.generate_private_key(cls.RSA_KEY_EXPONENT, cls.RSA_KEY_SIZE)

    def import_public_key(self, name, public_key, force=False):
        """
        Imports a public key in the directory
        :param str name: The name of the owner of the public key
        :param rsa.RSAPublicKey public_key: The public key to import
        :param bool force: True to overwrite an existing key
        :return None:
        """
        if name in self.public_keys_directory and not force:
            raise Exception("Error: a public key with this name "
                            "is already imported. Use force=True to overwrite it")

        if name in self.public_keys_directory and force:
            print("Warning: overwriting existing public key")

        self.public_keys_directory[name] = public_key

    def get_public_key(self):
        """
        Returns the public key of the person
        :return rsa.RSAPublicKey: The public key
        """
        return self.key.public_key()

    def generate_new_aes_key(self):
        """
        Generates a new random AES key
        :return bytes: The generated AES key
        """
        self.aes_key = os.urandom(self.AES_KEY_SIZE_BITS // 8)

    @classmethod
    def get_random_iv(cls):
        """
        Generates a new random initialization vector
        :return bytes: The generated IV
        """
        return os.urandom(16)

    def import_aes_key(self, key, force=False):
        """
        Imports an AES key
        :param force: True to overwrite an existing key
        :param bytes key: The AES key to import
        :return None:
        """
        if self.aes_key is not None and force:
            print("Warning: overwriting existing AES key")

        elif self.aes_key is not None and not force:
            raise Exception("Error: an AES key is already imported. Use force=True to overwrite it")

        self.aes_key = key

    def aes_encrypt(self, message):
        """
        Encrypts the given data with the existing AES key
        :param bytes|str message: The data to encrypt
        :return tuple[bytes, bytes]: The encrypted data and the initialization vector
        """
        assert self.aes_key is not None, "You must generate an AES key first"

        if type(message) is str:
            message = message.encode('utf-8')

        iv_ = self.get_random_iv()
        cipher = Cipher(algorithms.AES256(self.aes_key), modes.OFB(iv_))
        encryptor = cipher.encryptor()

        return encryptor.update(message) + encryptor.finalize(), iv_

    def aes_decrypt(self, message, iv):
        """
        Decrypts the given data with the existing AES key and given initialization vector
        :param bytes message: The data to decrypt
        :param bytes iv: The initialization vector to use
        :return bytes: The decrypted data
        """
        assert self.aes_key is not None, "You must generate an AES key first"

        cipher = Cipher(algorithms.AES256(self.aes_key), modes.OFB(iv))
        decryptor = cipher.decryptor()

        return decryptor.update(message) + decryptor.finalize()

    def get_aes_key(self):
        """
        Returns the AES key
        :return bytes: The AES key
        """
        assert self.aes_key is not None, "You must generate an AES key first"
        return self.aes_key

    def sign(self, message=None, hash=None):
        """
        Signs the given data
        :param bytes message: The data to sign
        :return bytes: The signature
        """

        assert message is not None or hash is not None, \
            "You must specify either the message or the hash of the message"

        if hash is None:
            hash = hashes.Hash(self.HASH_ALGORITHM)
            hash.update(message)
            hash = hash.finalize()

        return self.key.sign(
            hash,
            padding.PSS(
                mgf=padding.MGF1(self.HASH_ALGORITHM),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(self.HASH_ALGORITHM)
        )

    def verify(self, signature, message=None, hash=None, name=None, public_key=None):
        """
        Verify the given signature for the given message.
        You can either give the message or the hash of the message, but not both.
        You can either give the name of the sender or their public key, but not both.
        If you give their name, the public key must have been imported before.

        :param bytes signature: The signature to verify
        :param bytes message: The message to verify
        :param bytes hash: The hash of the message to verify
        :param str name: The name of the sender
        :param public_key: The public key of the sender
        :return: True if the signature is valid, False if not
        """
        assert message is not None or hash is not None, \
            "You must specify either the message or the hash of the message"

        assert message is None or hash is None, \
            "You must specify either the message or the hash of the message, not both"

        assert public_key is not None or name is not None, \
            "You must specify either the public key or the name of the sender"

        assert public_key is None or name is None, \
            "You must specify either the public key or the name of the sender, not both"

        # if the hash is not given, we compute it
        if hash is None:
            hash = hashes.Hash(self.HASH_ALGORITHM)
            hash.update(message)
            hash = hash.finalize()

        # if the public key is not given, we get it from the directory
        if name is not None:
            assert name in self.public_keys_directory, \
                "The name of the sender is not in the directory"
            public_key = self.public_keys_directory[name]

        # we verify the signature
        try:
            public_key.verify(
                signature,
                hash,
                padding.PSS(
                    mgf=padding.MGF1(self.HASH_ALGORITHM),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(self.HASH_ALGORITHM)
            )
            # signature verification succeeded because no exception was raised
            return True
        except:
            # signature verification failed
            return False

    def asymmetric_encrypt(self, message, public_key=None, name=None):
        """
        Encrypts the given data with the given public key or the public key of the given name.
        Either the public key or the name must be given, but not both.

        :param string|bytes message: The message to encrypt
        :param public_key: The public key to use
        :param name: The name of the recipient. Must have been imported before.
        :return: The encrypted data
        """
        assert public_key is not None or name is not None, \
            "You must specify either the public key or the name of the recipient"

        if name is not None:
            assert name in self.public_keys_directory, \
                "The name of the recipient is not in the directory"
            public_key = self.public_keys_directory[name]

        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None)
        )

    def asymmetric_decrypt(self, message):
        """
        Decrypts the given data with the person's private key
        :param message: The data to decrypt
        :return: The decrypted data
        """
        return self.key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
                algorithm=self.HASH_ALGORITHM,
                label=None)
        )

    def __str__(self):
        """
        Returns a string representation of the person with their name and public key
        :return: The string representation
        """
        return (self.name + ":\n" +
                self.key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
                )


if __name__ == "__main__":
    alice = Person("Alice")
    bob = Person("Bob")

    alice.import_public_key("bob", bob.get_public_key())
    bob.import_public_key("alice", alice.get_public_key())

    alice.generate_new_aes_key()
    ct = alice.asymmetric_encrypt(alice.get_aes_key(), name="bob")

    sig = alice.sign(ct)

    ok = bob.verify(sig, message=ct, name="alice")
    print("Signature is valid:", ok)

    print("trying to alter data")
    ct2 = ct[:-1] + b"0"

    ok = bob.verify(sig, message=ct2, name="alice")
    print("Signature is valid:", ok)

    dectext = bob.asymmetric_decrypt(ct)
    bob.import_aes_key(dectext)

    ct, iv = bob.aes_encrypt("Hello Alice, this is Bob")

    print(ct, iv)
    print(alice.aes_decrypt(ct, iv))

    ct, iv = alice.aes_encrypt("Hi, thank you for your message")

    print(ct, iv)

    print(bob.aes_decrypt(ct, iv))
