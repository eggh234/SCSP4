import requests
import base64
import json
import os
from cryptography.hazmat.primitives import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# TODO: import additional modules as required

gt_username = "yhuang916"  # TODO: Replace with your gt username within quotes
server_name = "secure-shared-store"

# These need to be created manually before you start coding.
node_certificate = "/home/cs6238/Desktop/Project4/client1/certs/client1.crt"
node_key = "/home/cs6238/Desktop/Project4/client1/certs/client1.key"

""" <!!! DO NOT MODIFY THIS FUNCTION !!!>"""


def post_request(server_name, action, body, node_certificate, node_key):
    """
    node_certificate is the name of the certificate file of the client node (present inside certs).
    node_key is the name of the private key of the client node (present inside certs).
    body parameter should in the json format.
    """
    request_url = "https://{}/{}".format(server_name, action)
    request_headers = {"Content-Type": "application/json"}
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
        verify="/home/cs6238/Desktop/Project4/CA/CA.crt",
        timeout=(10, 20),
    )
    with open(gt_username, "wb") as f:
        f.write(response.content)

    return response


""" You can begin modification from here"""


def sign_statement(statement, user_private_key_file):
    # sign the statement withe the users private key
    with open(user_private_key_file, "rb") as key_file:

        user_private_key_file = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    signed_statement = user_private_key_file.sign(
        statement.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signed_statement


def login():
    """
    # TODO: Accept the
     - user-id
     - name of private key file(should be present in the userkeys folder) of the user.
    Generate the login statement as given in writeup and its signature.
    Send request to server with required parameters (Ex: action = 'login') using the
    post_request function given.
    The request body should contain the user-id, statement and signed statement.
    """

    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = input(" User Id: ") or "user1"

        # get the user private key filename or default to user1.key
        private_key_filename = input(" Private Key Filename: ") or "user1.key"

        # complete the full path of the user private key filename (depends on the client)
        # Ex: '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename
        user_private_key_file = (
            "/home/cs6238/Desktop/Project4/client1/userkeys/" + private_key_filename
        )

        # create the statement
        statement = "statement"
        signed_statement = sign_statement(statement, user_private_key_file)

        body = {
            "user-id": user_id,
            "statement": statement,
            "signed-statement": base64.b64encode(signed_statement).decode("utf8"),
        }

        server_response = post_request(
            server_name, "login", body, node_certificate, node_key
        )

        if server_response.json().get("status") == 200:
            successful_login = True
        else:
            print(server_response.json().get("statement", "Try again"))

    return server_response.json()


def checkin(session_token):
    """
    # TODO: Accept the
     - DID: document id (filename)
     - security flag (1 for confidentiality  and 2 for integrity)
    Send the request to server with required parameters (action = 'checkin') using post_request().
    The request body should contain the required parameters to ensure the file is sent to the server.
    """

    # copy paste file from client to server
    # if flag is 1 then encrypt with randomly generated key and store it in metadata while encrypted with servers public key
    # if flag is 2 then you create a signature for the file
    # server store the aes key inside the json file in documents folder

    # Get security flag from user
    while True:
        try:
            security_flag = int(
                input("Please enter a flag (1 for confidentiality, 2 for integrity): ")
            )
            if security_flag in [1, 2]:
                print("security flag")
                print(security_flag)
                break
            else:
                print("Invalid input. Please enter either 1 or 2.")
        except ValueError:
            print("Invalid input. Please use numeric values.")

    # Get document ID from user
    file_name = input("Please enter the file name: ")
    client_checkin_file_path = os.path.join(
        "/home/cs6238/Desktop/Project4/client1/documents/checkin",
        file_name,
    )

    if not os.path.isfile(client_checkin_file_path):
        print(
            f"File not found at {client_checkin_file_path}. Please check the filename and try again."
        )
        return None

    # Read file content
    try:
        with open(client_checkin_file_path, "rb") as file:
            file_data = file.read()
            print("file path")
            print(client_checkin_file_path)
            print("file data")
            print(file_data)
    except IOError as e:
        print(f"Error reading file {client_checkin_file_path}: {e}")
        return None

    body = {
        "security_flag": security_flag,
        "document_id": file_name,
        "file_data": file_data,
        "token": session_token,
    }
    server_response = post_request(
        server_name, "checkin", body, node_certificate, node_key
    )
    return server_response.json()

    # return None


def checkout(session_token):
    """
    # TODO:
    Send request to server with required parameters (action = 'checkout') using post_request()
    """

    return


def grant(session_token):
    """
    # TODO:
     - DID
     - target user to whom access should be granted (0 for all user)
     - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
     - time duration (in seconds) for which access is granted
    Send request to server with required parameters (action = 'grant') using post_request()
    """

    return


def delete(session_token):
    """
    # TODO:
    Send request to server with required parameters (action = 'delete')
    using post_request().
    """

    return


def logout(session_token):
    """
    # TODO: Ensure all the modified checked out documents are checked back in.
    Send request to server with required parameters (action = 'logout') using post_request()
    The request body should contain the user-id, session-token
    """

    return


def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")

    return


def main():
    """
    # TODO: Authenticate the user by calling login.
    If the login is successful, provide the following options to the user
        1. Checkin
        2. Checkout
        3. Grant
        4. Delete
        5. Logout
    The options will be the indices as shown above. For example, if user
    enters 1, it must invoke the Checkin function. Appropriate functions
    should be invoked depending on the user input. Users should be able to
    perform these actions in a loop until they logout. This mapping should
    be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = "UNKNOWN"
    server_status = "UNKNOWN"
    session_token = "UNKNOWN"
    is_login = False

    # test()
    # return
    login_return = login()

    server_message = login_return["message"]
    server_status = login_return["status"]
    session_token = login_return["session_token"]

    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        print_main_menu()
        user_choice = input()
        if user_choice == "1":
            checkin(session_token)
        elif user_choice == "2":
            checkout(session_token)
        elif user_choice == "3":
            grant(session_token)
        elif user_choice == "4":
            delete(session_token)
        elif user_choice == "5":
            logout(session_token)
        else:
            print("not a valid choice")


if __name__ == "__main__":
    main()
