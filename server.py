from cryptography.hazmat.primitives import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
import os
import base64
import glob
import secrets
import time
import threading
import time
import os
import json

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)


class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"


def verify_statement(statement, signed_statement, user_public_key_file):
    try:
        with open(user_public_key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend()
            )

        # Verify the signature
        public_key.verify(
            signed_statement,
            statement.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Signature verified")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
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
        user_id = data["user_id"]
        statement = data["statement"]
        signed_statement = base64.b64decode(data["signed_statement"])
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )

        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )
        # complete the full path of the user public key filename
        # /home/cs6238/Desktop/Project4/server/application/userpublickeys/{user_public_key_filename}
        user_public_key_file = (
            "/home/cs6238/Desktop/Project4/server/application/userpublickeys/"
            + user_id
            + ".pub"
        )

        success = verify_statement(statement, signed_statement, user_public_key_file)

        if success:

            # Ensure the directory exists
            if not os.path.exists(server_document_folder):
                os.makedirs(server_document_folder, exist_ok=True)

            # Check if the session file already exists and contains the user_id
            if os.path.isfile(session_file_path):
                with open(session_file_path, "r") as file:
                    try:
                        session_data = json.load(file)
                        # Verify user ID
                        meta_user_id = session_data.get("user_id", 0)
                        session_token = session_data.get("session_token", 0)
                        if meta_user_id == user_id:
                            response = {
                                "status": 200,
                                "message": "Login Successful, Token Found",
                                "session_token": session_token,
                            }
                            return jsonify(response)

                    except json.JSONDecodeError:
                        # Handle empty or invalid JSON
                        print("Invalid session token value")
                        response = {
                            "status": 700,
                            "message": "Login Failed",
                            "session_token": "INVALID",
                        }
                        return jsonify(response)
            else:
                # Generate a new session token if not found or if file doesn't exist
                new_session_token = secrets.token_urlsafe(5)

                # Write or update the session file with new user ID and token
                session_data = {"user_id": user_id, "session_token": new_session_token}
                with open(session_file_path, "w") as json_file:
                    json.dump(session_data, json_file)

                print(f"user_id and session_token stored at {session_file_path}")

                response = {
                    "status": 200,
                    "message": "Login Successful, Token Generated",
                    "session_token": new_session_token,
                }
                return jsonify(response)
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
        user_id = data.get("user_id")
        user_session_token = data.get("session_token")
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
        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )

        # Ensure the directory exists before creating files
        os.makedirs(os.path.dirname(session_file_path), exist_ok=True)

        # Load AES key metadata from file
        with open(session_file_path, "r") as file:
            session_data = json.load(file)

        # Verify user session token
        server_sesion_token = session_data.get("session_token", 0)
        if user_session_token != server_sesion_token:
            response = {"status": 700, "message": "Session token mismatch"}
            return jsonify(response)

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

                # Write or overwrite the file with the provided data, decoding it from base64
                with open(server_checkin_file_path, "wb") as file:
                    file.write(base64.b64decode(client_file_data))

                print(f"File created (or overwritten) at {server_checkin_file_path}")

                # Store AES key, IV, and user ID in the metadata file
                aes_metadata = {
                    "aes_key": base64.b64encode(aes_key).decode("utf-8"),
                    "iv": base64.b64encode(aes_iv).decode("utf-8"),
                    "security_flag": security_flag,
                    "user_id": user_id,  # Adding the user ID
                    "grant_code": 3,
                }
                with open(aes_metadata_path, "w") as json_file:
                    json.dump(aes_metadata, json_file)
                print(f"AES key, IV, and user id stored in {aes_metadata_path}")

                # os.remove(client_checkin_file_path)
                # print("File processed successfully")

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
                        "grant_code": 3,
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

                    # os.remove(client_checkin_file_path)
                    # print("File processed successfully")

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
        user_session_token = data.get("session_token")
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

        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )

        signed_file_path = filename + ".sign"

        # Ensure the directory exists before creating files
        os.makedirs(os.path.dirname(session_file_path), exist_ok=True)

        # Load session data metadata from file
        with open(session_file_path, "r") as file:
            session_data = json.load(file)

        # Verify user session token
        server_sesion_token = session_data.get("session_token", 0)
        if user_session_token != server_sesion_token:
            response = {"status": 700, "message": "Session token mismatch"}
            return jsonify(response)

        # Checks for the existence of the necessary files
        if not os.path.isfile(server_checkout_file_path):
            response = {"status": 704, "message": "File not found on the server"}

        if not os.path.isfile(aes_metadata_path):
            response = {"status": 704, "message": "Encryption metadata not found"}

        # Load AES key metadata from file
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        # Verify user ID from metadata
        aes_user_id = aes_metadata.get("user_id")

        # Pattern to match files
        file_pattern = f"{server_document_folder}/filename_{user_id}_aes_key.txt.json"

        # Use glob to find matching files
        matching_files = glob.glob(file_pattern)

        # Check if any of the conditions are true
        if aes_user_id == user_id or matching_files:
            # If user_id matches or files exist, continue processing
            pass  # Replace 'pass' with actual processing code
        else:
            # If neither condition is met, return access denied
            response = {"status": 702, "message": "Access denied"}
            return jsonify(response)

        # Read the security flag from the metadata
        security_flag = aes_metadata.get("security_flag", 0)

        # Process based on the security flag
        if security_flag == 1:
            # Decrypt the file using the AES key and IV from the metadata file
            aes_key_base64 = aes_metadata["aes_key"]
            aes_iv_base64 = aes_metadata["iv"]
            key = base64.b64decode(aes_key_base64)
            iv = base64.b64decode(aes_iv_base64)
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            with open(server_checkout_file_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Write the decrypted data to the client's checkout path
            with open(client_file_path, "wb") as file:
                file.write(decrypted_data)  # Write decrypted data directly

            try:
                # Delete the specified file and its metadata
                os.remove(server_checkout_file_path)
                print("file processed successfully")

                response = {
                    "status": 200,
                    "message": "Document successfully checked out",
                }
                return jsonify(response)
            
            except Exception as e:
                response = {
                    "status": 700,
                    "message": "File processed unsuccessfully " + str(e),
                }
                return jsonify(response)

        elif security_flag == 2:
            # Verify integrity with the signature
            signed_file_path = os.path.join(server_document_folder, filename + ".sign")

            if not os.path.isfile(signed_file_path):
                print("Signature file not found")
                response = {"status": 704, "message": "Signature file not found"}
                return jsonify(response)

            # Load the server's public key for signature verification
            with open(server_public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
            print("Public key loaded")

            # Read the signature
            with open(signed_file_path, "rb") as sign_file:
                signature = sign_file.read()

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

            except cryptography.exceptions.InvalidSignature:
                print("Invalid signature")
                response = {"status": 703, "message": "Invalid signature"}
                return jsonify(response)
            except Exception as e:
                print(f"An exception occurred during signature verification: {e}")
                response = {"status": 700, "message": "Signature verification failed"}
                return jsonify(response)

            try:
                # Delete the specified file and its metadata
                os.remove(server_checkout_file_path)
                print("File processed successfully")

                response = {
                    "status": 200,
                    "message": "Document successfully checked out and signature verified",
                }
            except Exception as e:
                print(f"An exception occurred while deleting the file: {e}")
                response = {
                    "status": 700,
                    "message": "Other Errors " + str(e),
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
        user_session_token = data.get("session_token")
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )

        filename = data.get("document_id")

        aes_metadata_path = os.path.join(
            server_document_folder, filename + "_AES_Key.txt.json"
        )

        server_checkout_file_path = os.path.join(server_document_folder, filename)

        user_id = data.get("user_id")
        target_grant_user = data.get("user_grant")
        user_timer = data.get("user_timer")
        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )
        target_grant_code = data.get("grant_code")
        aes_metadata = {
            "user_id": target_grant_user,  # Adding the user ID
            "grant_code": target_grant_code,
        }
        temp_access = os.path.join(
            server_document_folder, filename + "_" + target_grant_user + "_AES_Key.txt.json"
        )
        temp_metadata = {
            "user_id": target_grant_user,  # Adding the user ID
            "grant_code": target_grant_code,
        }
        # Retrieve 'user_timer' from the data dictionary and safely convert it to an integer
        try:
            user_timer = int(data.get("user_timer", "0"))  # Default to 0 if 'user_timer' is not found
        except ValueError:
            print("Invalid timer value. Setting to default of 0 seconds.")
            user_timer = 0

        # Ensure the directory exists before creating files
        os.makedirs(os.path.dirname(session_file_path), exist_ok=True)

        # Load session data metadata from file
        with open(session_file_path, "r") as file:
            session_data = json.load(file)

        # Verify user session token
        server_sesion_token = session_data.get("session_token", 0)
        if user_session_token != server_sesion_token:
            response = {"status": 700, "message": "Session token mismatch"}
            return jsonify(response)

        # Check for the existence of the file and metadata
        if not os.path.isfile(server_checkout_file_path) or not os.path.isfile(
            aes_metadata_path
        ):
            response = {
                "status": 700,
                "message": "File or metadata not found on the server",
            }

        # Load AES key metadata from file
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        # Check if user id matches
        aes_user_id = aes_metadata.get("user_id", 0)
        if aes_user_id != user_id:
            response = {"status": 702, "message": "Access denied to grant access"}
            return jsonify(response)

        # Checks for the existence of the necessary files
        if not os.path.isfile(server_checkout_file_path):
            response = {"status": 700, "message": "File not found on the server"}

        if not os.path.isfile(aes_metadata_path):
            response = {"status": 700, "message": "Metadata not found"}

        # Load AES key metadata from file
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        aes_user_id = aes_metadata.get("user_id", 0)
        if aes_user_id != user_id:
            response = {"status": 702, "message": "Access denied to grant access"}
            return jsonify(response)

        # Read the grant flag from the metadata
        actual_grant_flag = aes_metadata.get("grant_code", 0)

        if actual_grant_flag == 1:
            with open(temp_access, "w") as json_file:
                json.dump(temp_metadata, json_file)
            print(f"user id stored in {temp_access}")

            # Immediate response
            response = {"status": 200, "message": "Successfully granted access"}
            response_output = jsonify(response)

            # Define and start a thread to handle the delay and subsequent actions
            def handle_delayed_tasks():
                print(f"Timer set for {user_timer} seconds.")
                time.sleep(user_timer)  # Wait for the duration set in user_timer
                print("Timer ended. Performing the action now.")  # Action after timer ends

                # Delete the file after the timer ends
                os.remove(temp_access)
                print(f"File {temp_access} has been removed.")
        
        if actual_grant_flag == 2:
            with open(temp_access, "w") as json_file:
                json.dump(temp_metadata, json_file)
            print(f"user id stored in {temp_access}")

            # Immediate response
            response = {"status": 200, "message": "Successfully granted access"}
            response_output = jsonify(response)

            # Define and start a thread to handle the delay and subsequent actions
            def handle_delayed_tasks():
                print(f"Timer set for {user_timer} seconds.")
                time.sleep(user_timer)  # Wait for the duration set in user_timer
                print("Timer ended. Performing the action now.")  # Action after timer ends

                # Delete the file after the timer ends
                os.remove(temp_access)
                print(f"File {temp_access} has been removed.")

            thread = threading.Thread(target=handle_delayed_tasks)
            thread.start()

            return response_output


        if actual_grant_flag == 3:
            with open(temp_access, "w") as json_file:
                json.dump(temp_metadata, json_file)
            print(f"user id stored in {temp_access}")

            # Immediate response
            response = {"status": 200, "message": "Successfully granted access"}
            response_output = jsonify(response)

            # Define and start a thread to handle the delay and subsequent actions
            def handle_delayed_tasks():
                print(f"Timer set for {user_timer} seconds.")
                time.sleep(user_timer)  # Wait for the duration set in user_timer
                print("Timer ended. Performing the action now.")  # Action after timer ends

                # Delete the file after the timer ends
                os.remove(temp_access)
                print(f"File {temp_access} has been removed.")

            thread = threading.Thread(target=handle_delayed_tasks)
            thread.start()

            return response_output




class delete(Resource):
    """
    Expected response status codes:
    1) 200 - Successfully deleted the file
    2) 702 - Access denied deleting file
    3) 704 - File or metadata not found on the server
    4) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        filename = data.get("document_id")
        user_id = data.get("user_id")
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )
        server_checkout_file_path = os.path.join(server_document_folder, filename)

        aes_metadata_path = os.path.join(
            server_document_folder, filename + "_AES_Key.txt.json"
        )
        user_session_token = data.get("session_token")

        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )

        # Ensure the directory exists before creating files
        os.makedirs(os.path.dirname(session_file_path), exist_ok=True)

        # Load session data metadata from file
        with open(session_file_path, "r") as file:
            session_data = json.load(file)

        # Verify user session token
        server_sesion_token = session_data.get("session_token", 0)
        if user_session_token != server_sesion_token:
            response = {"status": 700, "message": "Session token mismatch"}
            return jsonify(response)

        # Check for the existence of the file and metadata
        if not os.path.isfile(server_checkout_file_path) or not os.path.isfile(
            aes_metadata_path
        ):
            response = {
                "status": 704,
                "message": "File or metadata not found on the server",
            }

        # Load AES key metadata from file
        with open(aes_metadata_path, "r") as file:
            aes_metadata = json.load(file)

        # Check if user id matches
        aes_user_id = aes_metadata.get("user_id", 0)
        if aes_user_id != user_id:
            response = {"status": 702, "message": "Access denied deleting file"}
            return jsonify(response)

        try:
            # Delete the specified file and its metadata
            os.remove(server_checkout_file_path)
            os.remove(aes_metadata_path)

            # Also delete any files that include the filename in their name
            pattern = os.path.join(server_document_folder, filename + "*")
            for file in glob.glob(pattern):
                os.remove(file)
            response = {
                "status": 200,
                "message": "Successfully deleted the file and associated data",
            }
        except Exception as e:
            response = {
                "status": 700,
                "message": "Failed to delete the files: " + str(e),
            }

        return jsonify(response)


class logout(Resource):
    def post(self):
        """
        Expected response status codes:
        1) 200 - Successfully logged out
        2) 700 - Failed to log out
        """
        data = request.get_json()
        user_id = data.get("user_id")
        server_document_folder = (
            "/home/cs6238/Desktop/Project4/server/application/documents"
        )
        session_file_path = os.path.join(
            server_document_folder, user_id + "_session.txt"
        )

        user_session_token = data.get("session_token")
        # Ensure the directory exists before creating files
        os.makedirs(os.path.dirname(session_file_path), exist_ok=True)

        # Load session data metadata from file
        with open(session_file_path, "r") as file:
            session_data = json.load(file)

        # Verify user session token
        server_sesion_token = session_data.get("session_token", 0)
        if user_session_token != server_sesion_token:
            response = {"status": 700, "message": "Session token mismatch"}
            return jsonify(response)

        # List all metadata files
        metadata_files = [
            f
            for f in os.listdir(server_document_folder)
            if f.endswith("_AES_Key.txt.json")
        ]

        # Read user_id from each metadata file and check if the corresponding file exists
        for metadata_file in metadata_files:
            with open(os.path.join(server_document_folder, metadata_file), "r") as file:
                metadata = json.load(file)

            if metadata["user_id"] == user_id:
                filename = metadata_file.replace("_AES_Key.txt.json", "")

                if not os.path.isfile(os.path.join(server_document_folder, filename)):
                    # File not checked in, ask the user to check in
                    response = {
                        "status": 700,
                        "message": "Not all files were checked back in",
                    }
                    return jsonify(response)

            # All files checked in, remove user's session
        pattern = os.path.join(server_document_folder, user_id + "*")
        for file in glob.glob(pattern):
            os.remove(file)
        print(f"Session for user ID {user_id} has been deleted.")
        response = {"status": 200, "message": "Sucessfully logged out"}
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
