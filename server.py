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
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask import jsonify
from flask import request

# TODO: import additional modules as required
import base64
import json
import shutil
import os


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
        response = {}

        if security_flag == 1:
            try:
                server_document_folder = (
                    "/home/cs6238/Desktop/Project4/server/application/documents"
                )
                server_checkin_file_path = os.path.join(
                    server_document_folder, filename
                )
                aes_metadata_path = os.path.join(
                    server_document_folder, filename + "_AES_Key.txt.json"
                )
                server_public_key_path = (
                    "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub"
                )
                server_private_key_path = (
                    "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key"
                )

                # Ensure the directory exists before creating files
                os.makedirs(os.path.dirname(server_checkin_file_path), exist_ok=True)

                # Write or overwrite the file with the provided data
                with open(server_checkin_file_path, "wb") as file:
                    file.write(
                        client_file_data.encode()
                    )  # Ensure client_file_data is a string. If it's already bytes, remove .encode()

                print(f"File created (or overwritten) at {server_checkin_file_path}")

                # Encrypt the file with the server's public key
                with open(server_public_key_path, "rb") as key_file:
                    public_key = serialization.load_pem_public_key(
                        key_file.read(), backend=default_backend()
                    )

                encrypted_file_data = public_key.encrypt(
                    client_file_data.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # Write the encrypted file data to the server file
                with open(server_checkin_file_path, "wb") as file:
                    file.write(encrypted_file_data)
                print(f"File {filename} encrypted with the server's public key.")

                # Generate an AES key and IV for encrypting the server's private key
                aes_key = os.urandom(32)  # AES-256 key
                aes_iv = os.urandom(16)  # Initialization vector for AES
                cipher = Cipher(
                    algorithms.AES(aes_key),
                    modes.CFB(aes_iv),
                    backend=default_backend(),
                )
                encryptor = cipher.encryptor()

                # Load and encrypt the server's private key
                with open(server_private_key_path, "rb") as key_file:
                    private_key_data = key_file.read()

                encrypted_private_key_data = (
                    encryptor.update(private_key_data) + encryptor.finalize()
                )

                # Store AES key, IV, encrypted private key, and security flag in the metadata file
                aes_metadata = {
                    "aes_key": base64.b64encode(aes_key).decode("utf-8"),
                    "iv": base64.b64encode(aes_iv).decode("utf-8"),
                    "encrypted_private_key": base64.b64encode(
                        encrypted_private_key_data
                    ).decode("utf-8"),
                    "security_flag": security_flag,  # Storing the security flag
                }
                with open(aes_metadata_path, "w") as json_file:
                    json.dump(aes_metadata, json_file)
                print(
                    f"AES key, encrypted server private key, and security flag stored in {aes_metadata_path}"
                )

                # If all operations complete successfully, set success to True
                success = True

            except Exception as e:
                print(f"An exception occurred: {e}")
                success = False

        elif security_flag == 2:
            try:
                # Path setup
                server_document_folder = (
                    "/home/cs6238/Desktop/Project4/server/application/documents"
                )
                server_checkin_file_path = os.path.join(
                    server_document_folder, filename
                )
                server_public_key_path = (
                    "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub"
                )
                server_private_key_path = (
                    "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key"
                )
                aes_metadata_path = os.path.join(
                    server_document_folder, filename + "_AES_Key.txt.json"
                )

                # Encrypt the file with the server's public key
                with open(server_public_key_path, "rb") as key_file:
                    public_key = serialization.load_pem_public_key(
                        key_file.read(), backend=default_backend()
                    )

                # Write or overwrite the file with the provided data
                with open(server_checkin_file_path, "wb") as file:
                    file.write(
                        client_file_data.encode()
                    )  # Ensure client_file_data is a string. If it's already bytes, remove .encode()

                print(f"File created (or overwritten) at {server_checkin_file_path}")

                encrypted_file_data = public_key.encrypt(
                    client_file_data.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # Write the encrypted file data to the server file
                with open(server_checkin_file_path, "wb") as file:
                    file.write(encrypted_file_data)

                # Sign the encrypted file with the server's private key
                with open(server_private_key_path, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # Replace with the private key password if needed
                        backend=default_backend(),
                    )

                signature = private_key.sign(
                    encrypted_file_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                # Write the signature to a .sign file
                signature_file_path = f"{server_checkin_file_path}.sign"
                with open(signature_file_path, "wb") as sign_file:
                    sign_file.write(signature)

                # Generate an AES key and IV for future operations
                aes_key = os.urandom(32)  # AES-256 key
                aes_iv = os.urandom(16)  # Initialization vector for AES

                # Store AES key, IV, and security flag in the metadata file
                aes_metadata = {
                    "aes_key": base64.b64encode(aes_key).decode("utf-8"),
                    "iv": base64.b64encode(aes_iv).decode("utf-8"),
                    "security_flag": security_flag,  # Storing the security flag
                }
                with open(aes_metadata_path, "w") as json_file:
                    json.dump(aes_metadata, json_file)

                success = True

            except Exception as e:
                print(f"An exception occurred: {e}")
                success = False

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
        print("aes path")
        print(aes_metadata_path)
        client_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/client1/documents/checkout", filename
        )
        signed_file_path = os.path.join(server_document_folder, f"{filename}.sign")

        # Checks for the existence of the necessary files
        if not os.path.isfile(server_checkout_file_path):
            return (
                ({"status": 704, "message": "File not found on the server"}),
                704,
            )

        if not os.path.isfile(aes_metadata_path):
            print("file not found")
            return (
                ({"status": 700, "message": "Encryption metadata not found"}),
                700,
            )

        # Load AES metadata
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        aes_key_base64 = aes_metadata["aes_key"]
        aes_iv_base64 = aes_metadata["iv"]
        key = base64.b64decode(aes_key_base64)
        iv = base64.b64decode(aes_iv_base64)
        security_flag = aes_metadata["security_flag"]

        # Process based on the security flag
        if security_flag == 1:
            print("flag1")
            # Just decrypt and copy the data to the client's checkout path
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            with open(server_checkout_file_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            with open(client_file_path, "wb") as file:
                file.write(decrypted_data)
            return (
                ({"status": 200, "message": "Document Successfully checked out"}),
                200,
            )

        elif security_flag == 2:
            print("flag2")
            # Verify integrity and decrypt
            if not os.path.isfile(signed_file_path):
                print("check signed file path")
                return (
                    ({"status": 700, "message": "Signature file not found"}),
                    700,
                )

            # Load the public key for verification
            with open(
                "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub",
                "rb",
            ) as key_file:
                public_key = load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
            print("open public key")
            # Read the encrypted data
            with open(server_checkout_file_path, "rb") as file:
                encrypted_data = file.read()

            # Read the signature
            with open(signed_file_path, "rb") as sign_file:
                signature = sign_file.read()

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
                print("verify signature")
            except cryptography.exceptions.InvalidSignature:
                return (
                    (
                        {
                            "status": 703,
                            "message": "Check out failed due to broken integrity",
                        }
                    ),
                    703,
                )
            except Exception:
                return (
                    ({"status": 700, "message": "Signature verification failed"}),
                    700,
                )

            # Decrypt the data if signature is valid
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Write the decrypted data to the client's directory
            with open(client_file_path, "wb") as file:
                file.write(decrypted_data)
            return (
                ({"status": 200, "message": "Document Successfully checked out"}),
                200,
            )

        else:
            # Handle unexpected security_flag values
            return ({"status": 700, "message": "Ending failure"}), 700


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
