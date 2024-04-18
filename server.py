from cryptography.hazmat.primitives import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
            # Similar response format given below can be used for all the other functions
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
    def post(self):
        data = request.get_json()

    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    # make checkin randomly generated tokens
    # make a metadata file
    # metadata = {
    # client side             'doc_id': doc_id,
    #             'owner': owner,
    # client side             'security_flag': security_flag,
    #             'grant_user':"",
    #             'grant_token' : "",
    #             'grant_access' : "",
    #             'aes_key' : ""

    #         }
    # ask client for file path to file1 or file2
    # open the file
    # make a body request
    # send it to the server including DID security flag and token

    # on server side
    # generate a Key with AES GPT this part
    # encrypt the file1 or file 2 with the AES key and maintain the key in the metadata in the server side
    # confidentiaity

    # integrity
    # sign the file with the key
    # when client requests file you sign it with the servers private key
    # create a .sign folder
    # use the .sign and the normal
    # i have a servers private key and i want to sign a file at this location how do i do this GPT
    # ask for decryption methods as well for GPT for the checkout part

    security_flag = data["security_flag"]
    filename = data["document_id"]
    client_file_data = data["file_data"]
    print(security_flag)
    print()

    server_checkin_file_path = os.path.join(
        "/home/cs6238/Desktop/Project4/server/application/documents", filename
    )
    client_checkin_file_path = os.path.join(
        "/home/cs6238/Desktop/Project4/client1/documents/checkin",
        filename,
    )
    json_metadata_path = os.path.join(
        "/home/cs6238/Desktop/Project4/server/application/documents",
        f"{filename}.json",
    )

    # Ensure the directory exists before creating files
    def handle_file_checkin(
        client_checkin_file_path,
        server_checkin_file_path,
        json_metadata_path,
        security_flag,
    ):
        # Ensure server directory exists
        os.makedirs(os.path.dirname(server_checkin_file_path), exist_ok=True)
        os.makedirs(os.path.dirname(json_metadata_path), exist_ok=True)
        print("path")
        print(server_checkin_file_path)
        print(client_checkin_file_path)
        # Initialize metadata JSON file
        if not os.path.exists(json_metadata_path):
            with open(json_metadata_path, "w") as file:
                json.dump(
                    {}, file
                )  # Create an empty JSON object if file does not exist

        # Read file content on the client side
        try:
            with open(client_checkin_file_path, "rb") as file:
                file_data = file.read()
                print("file data")
                print(file_data)
        except IOError as e:
            print(f"Error reading file {client_checkin_file_path}: {e}")
            return

        if security_flag == 1:
            # Encrypt the file and generate key
            key = os.urandom(32)  # AES-256 key
            iv = os.urandom(16)  # Initialization vector for AES
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()
            with open(client_checkin_file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()

            # Write the encrypted data to the server file
            with open(server_checkin_file_path, "wb") as file:
                file.write(iv + encrypted_data)  # Store IV with the data

            # Convert key to hexadecimal and store in JSON file
            metadata = {"key": key.hex(), "iv": iv.hex()}
            with open(json_metadata_path, "w") as json_file:
                json.dump(metadata, json_file)
            print("File successfully encrypted.")
        else:
            print(security_flag)

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
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
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
