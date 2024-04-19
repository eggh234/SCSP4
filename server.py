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
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        security_flag = data.get("security_flag")
        filename = data.get("document_id")
        client_file_data = data.get("file_data")

        server_checkin_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents", filename
        )
        json_metadata_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents",
            f"{filename}.json",
        )

        server_key_path = (
            "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub"
        )
        signed_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents",
            f"{filename}.sign",
        )

        os.makedirs(os.path.dirname(server_checkin_file_path), exist_ok=True)
        os.makedirs(os.path.dirname(json_metadata_path), exist_ok=True)

        if not os.path.exists(server_checkin_file_path):
            try:
                with open(server_checkin_file_path, "wb") as file:
                    file.write(client_file_data.encode())
                print(
                    f"New file created and data written to {server_checkin_file_path}"
                )
            except IOError as e:
                print(f"Error writing file {server_checkin_file_path}: {e}")
                return

        if security_flag == 1:
            key = os.urandom(32)  # AES-256 key
            iv = os.urandom(16)  # Initialization vector for AES
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = (
                encryptor.update(client_file_data.encode()) + encryptor.finalize()
            )

            with open(server_checkin_file_path, "wb") as file:
                file.write(iv + encrypted_data)

            metadata = {"key": key.hex(), "iv": iv.hex()}
            with open(json_metadata_path, "w") as json_file:
                json.dump(metadata, json_file)
            print("File successfully encrypted and stored.")

            response = {
                "status": 200,
                "message": "Document Successfully checked in",
            }

            with open(server_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # Replace with the password if the key is encrypted
                    backend=default_backend(),
                )

            # Sign file code start
            # Read the content of the file to be signed
            with open(server_checkin_file_path, "rb") as f:
                file_data = f.read()

            # Sign the data of the file
            signature = private_key.sign(
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Write the signature to a .sign file
            with open(signed_file_path, "wb") as sign_file:
                sign_file.write(signature)

            print(
                f"File {filename} has been signed. Signature stored at {signed_file_path}."
            )

        elif security_flag == 2:
            # Load the public key
            with open(server_key_path, "rb") as key_file:
                public_key = load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )

            # Read the document to verify
            with open(server_checkin_file_path, "rb") as file:
                document_data = file.read()

            # Read the signature from the .sign file
            with open(signed_file_path, "rb") as sign_file:
                signature = sign_file.read()

            # Verify the signature
            try:
                public_key.verify(
                    signature,
                    document_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                print("Verification successful: The signature is valid.")
            except cryptography.exceptions.InvalidSignature:
                print("Verification failed: The signature is not valid.")
            except Exception as e:
                print(f"An error occurred during the verification process: {e}")

        return jsonify(response)

    print("Unidentified Input")

    def post(self):
        data = request.get_json()
        token = data["token"]

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
        server_checkin_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents", filename
        )
        json_metadata_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents",
            f"{filename}.json",
        )
        client_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/client1/documents/checkout",
            filename,
        )
        signed_file_path = os.path.join(
            "/home/cs6238/Desktop/Project4/server/application/documents",
            f"{filename}.sign",
        )

        # Ensure encrypted data file exists
        if not os.path.exists(server_checkin_file_path):
            return (
                jsonify({"status": 704, "message": "File not found on the server"}),
                704,
            )

        # Ensure JSON metadata exists
        if not os.path.exists(json_metadata_path):
            return (
                jsonify({"status": 700, "message": "Encryption metadata not found"}),
                700,
            )

        # Ensure signature file exists
        if not os.path.exists(signed_file_path):
            return jsonify({"status": 700, "message": "Signature file not found"}), 700

        # Load public key for verifying signature
        with open(
            "/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub", "rb"
        ) as key_file:
            public_key = load_pem_public_key(key_file.read(), backend=default_backend())

        # Read the encrypted data
        with open(server_checkin_file_path, "rb") as file:
            document_data = file.read()

        # Read the signature
        with open(signed_file_path, "rb") as sign_file:
            signature = sign_file.read()

        # Verify the signature
        try:
            public_key.verify(
                signature,
                document_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except cryptography.exceptions.InvalidSignature:
            return (
                jsonify(
                    {
                        "status": 703,
                        "message": "Check out failed due to broken integrity",
                    }
                ),
                703,
            )
        except Exception as e:
            return (
                jsonify({"status": 700, "message": "Signature verification failed"}),
                700,
            )

        # If signature is verified, read AES key and IV from the JSON metadata file
        with open(json_metadata_path, "r") as file:
            metadata = json.load(file)
        key = bytes.fromhex(metadata["key"])
        iv = bytes.fromhex(metadata["iv"])

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(document_data) + decryptor.finalize()

        # Write the decrypted data to the client's directory
        with open(client_file_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        return (
            jsonify({"status": 200, "message": "Document Successfully checked out"}),
            200,
        )

    def post(self):
        data = request.get_json()
        token = data["token"]
        success = False
        if success:
            # Similar response format given below can be
            # used for all the other functions
            response = {
                "status": 200,
                "message": "Document Successfully checked out",
                "file": "file",
            }
        else:
            response = {
                "status": 702,
                "message": "Access denied checking out",
                "file": "Invalid",
            }
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
