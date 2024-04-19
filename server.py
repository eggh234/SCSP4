from cryptography.hazmat.primitives import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask
from flask_restful import Api, Resource
from flask import jsonify
from flask import request

# TODO: import additional modules as required
import base64
import json
import shutil
import os
import base64

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)


class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"


def verify_statement(statement, signed_statement, user_public_key_file):
    with open(user_public_key_file, "rb") as key_file:

        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    try:
        public_key.verify(
            signed_statement,
            statement.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True

    except:
        return False


class login(Resource):
    def post(self):
        data = request.get_json()
        # TODO: Implement login functionality
        """
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        """

        # Information coming from the client
        user_id = data["user-id"]
        statement = data["statement"]
        signed_statement = base64.b64decode(data["signed-statement"])

        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        user_public_key_file = (
            "/home/cs6238/Desktop/Project4/server/application/userpublickeys/"
            + user_id
            + ".pub"
        )

        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:
            session_token = "ABCD"
            response = {
                "status": 200,
                "message": "Login Successful",
                "session_token": session_token,
            }
        else:
            response = {
                "status": 700,
                "message": "Login Failed",
                "session_token": "INVALID",
            }
        return jsonify(response)


class checkin(Resource):
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    """

    def post(self):
        data = request.get_json()
        security_flag = data.get("security_flag")
        filename = data.get("document_id")
        client_file_data = data.get("file_data")
        user_id = data.get("user_id")
        response = {}
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )
        server_checkin_file_path = os.path.join(server_document_folder, filename)
        aes_metadata_path = os.path.join(
            server_document_folder, filename + "_AES_Key.txt.json"
        )
        server_private_key_path = (
            "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key"
        )

        if security_flag == 1:
            try:
                # Ensure the directory exists before creating files
                os.makedirs(os.path.dirname(server_checkin_file_path), exist_ok=True)

                # Generate an AES key and IV for encryption
                aes_key = os.urandom(32)  # AES-256 key
                aes_iv = os.urandom(16)  # Initialization vector
                cipher = Cipher(
                    algorithms.AES(aes_key),
                    modes.CFB(aes_iv),
                    backend=default_backend(),
                )
                encryptor = cipher.encryptor()

                # Encrypt the file data
                encrypted_file_data = (
                    encryptor.update(client_file_data.encode()) + encryptor.finalize()
                )

                # Overwrite the original file with encrypted data
                with open(server_checkin_file_path, "wb") as file:
                    file.write(encrypted_file_data)
                print(
                    f"File {filename} encrypted and saved at {server_checkin_file_path}."
                )

                # Store AES key, IV, and user ID in the metadata file
                aes_metadata = {
                    "aes_key": base64.b64encode(aes_key).decode("utf-8"),
                    "iv": base64.b64encode(aes_iv).decode("utf-8"),
                    "security_flag": security_flag,
                    "user_id": user_id,  # Adding the user ID
                }
                with open(aes_metadata_path, "w") as json_file:
                    json.dump(aes_metadata, json_file)
                print(f"AES key, IV, and user id stored in {aes_metadata_path}")

                success = True

            except Exception as e:
                print(f"An exception occurred: {e}")
                success = False

        elif security_flag == 2:
            try:
                # Ensure the directory exists before creating files
                os.makedirs(os.path.dirname(server_checkin_file_path), exist_ok=True)

                # Write or overwrite the file with the provided data, decoding it from base64
                with open(server_checkin_file_path, "wb") as file:
                    file.write(base64.b64decode(client_file_data))

                print(f"File created (or overwritten) at {server_checkin_file_path}")

                # Load the server's private key for signing the file data
                with open(server_private_key_path, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # Replace None with the password if the private key is encrypted
                        backend=default_backend(),
                    )

                # Read the file data to be signed
                if os.path.exists(server_checkin_file_path):
                    with open(server_checkin_file_path, "rb") as file:
                        file_data_to_sign = file.read()

                    # Store user ID and security flag in the metadata file
                    aes_metadata = {
                        "user_id": user_id,  # Adding the user ID
                        "security_flag": security_flag,
                    }
                    with open(aes_metadata_path, "w") as json_file:
                        json.dump(aes_metadata, json_file)
                    print(f"user id stored in {aes_metadata_path}")

                    success = True

                    # Sign the file data using the private key
                    signature = private_key.sign(
                        file_data_to_sign,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )

                    # Write the signature to a .sign file associated with the document
                    signature_file_path = server_checkin_file_path + ".sign"
                    with open(signature_file_path, "wb") as sign_file:
                        sign_file.write(signature)
                    print(f"Signature created and stored at {signature_file_path}")

                    response = {
                        "status": 200,
                        "message": "Document successfully signed and signature file created",
                    }
                else:
                    print("Error: Original file not found for signing.")
                    response = {
                        "status": 704,
                        "message": "Original file not found",
                    }

            except Exception as e:
                print(f"An exception occurred: {e}")
                response = {"status": 700, "message": "Signature process failed"}

        if success:
            response = {
                "status": 200,
                "message": "Document Successfully checked in",
            }
        else:
            response = {
                "status": 702,
                "message": "Access denied checking in",
            }

        return jsonify(response)


class checkout(Resource):
    """
    Expected response status codes:
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        filename = data.get("document_id")
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )

        server_checkout_file_path = os.path.join(server_document_folder, filename)

        aes_metadata_path = os.path.join(
            server_document_folder, filename + "_AES_Key.txt.json"
        )

        user_id = data.get("user_id")

        client_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/client1/documents/checkout", filename
        )

        server_public_key_path = (
            "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub"
        )

        signed_file_path = filename + ".sign"

        # Checks for the existence of the necessary files
        print("check1")
        if not os.path.isfile(server_checkout_file_path):
            response = {"status": 704, "message": "File not found on the server"}, 704

        if not os.path.isfile(aes_metadata_path):
            print("check2")
            response = {"status": 704, "message": "Encryption metadata not found"}, 704

        # Load AES key metadata from file
        print("check3")
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        # Verify user ID
        print("check4")
        if aes_metadata["user_id"] != user_id:
            response = {"status": 702, "message": "Access denied"}, 702

        # Read the security flag from the metadata
        security_flag = aes_metadata.get("security_flag", 0)
        print("check4")

        # Process based on the security flag
        if security_flag == 1:
            # Decrypt the file using the AES key and IV from the metadata file
            aes_key_base64 = aes_metadata["aes_key"]
            aes_iv_base64 = aes_metadata["iv"]
            key = base64.b64decode(aes_key_base64)
            iv = base64.b64decode(aes_iv_base64)
            print("check5")
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            with open(server_checkout_file_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Write the decrypted data to the client's checkout path
            with open(client_file_path, "wb") as file:
                file.write(decrypted_data)

            response = {
                "status": 200,
                "message": "Document successfully checked out",
            }, 200

        elif security_flag == 2:
            # Verify integrity with the signature
            signed_file_path = os.path.join(server_document_folder, filename + ".sign")
            if not os.path.isfile(signed_file_path):
                print("Signature file not found")
                response = {"status": 704, "message": "Signature file not found"}, 704

            # Read the signature
            with open(signed_file_path, "rb") as sign_file:
                signature = sign_file.read()

            # Load the server's public key for signature verification
            with open(server_public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
            print("Public key loaded")

            # Read the encrypted data
            with open(server_checkout_file_path, "rb") as file:
                encrypted_data = file.read()

            # Verify the signature
            try:
                public_key.verify(
                    signature,
                    encrypted_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                print("Signature verified")

                # Since the signature is verified, copy the encrypted data to the client's path
                with open(client_file_path, "wb") as client_file:
                    client_file.write(encrypted_data)
                print("Encrypted file copied to client path")

                response = {
                    "status": 200,
                    "message": "Document successfully checked out and signature verified",
                }

            except cryptography.exceptions.InvalidSignature:
                print("Invalid signature")
                return {"status": 703, "message": "Invalid signature"}
            except Exception as e:
                print(f"An exception occurred during signature verification: {e}")
                response = {"status": 700, "message": "Signature verification failed"}

        return jsonify(response)


class grant(Resource):
    """
    Expected response status codes:
    1) 200 - Successfully granted access
    2) 702 - Access denied to grant access
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        token = data["token"]
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                "status": 200,
                "message": "Successfully granted access",
            }
        else:
            response = {
                "status": 702,
                "message": "Access denied to grant access",
            }
        return jsonify(response)


class delete(Resource):
    """
    Expected response status codes:
    1) 200 - Successfully deleted the file
    2) 702 - Access denied deleting file
    3) 704 - Delete failed since file not found on the server
    4) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        token = data["token"]
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                "status": 200,
                "message": "Successfully deleted the file",
            }
        else:
            response = {
                "status": 702,
                "message": "Access denied deleting file",
            }
        return jsonify(response)


class logout(Resource):
    def post(self):
        """
        Expected response status codes:
        1) 200 - Successfully logged out
        2) 700 - Failed to log out
        """

        def post(self):
            data = request.get_json()
            token = data["token"]

        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                "status": 200,
                "message": "Successfully logged out",
            }
        else:
            response = {
                "status": 700,
                "message": "Failed to log out",
            }
        return jsonify(response)


api.add_resource(welcome, "/")
api.add_resource(login, "/login")
api.add_resource(checkin, "/checkin")
api.add_resource(checkout, "/checkout")
api.add_resource(grant, "/grant")
api.add_resource(delete, "/delete")
api.add_resource(logout, "/logout")


def main():
    secure_shared_service.run(debug=True)


if __name__ == "__main__":
    main()
