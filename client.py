# FINAL VERSION

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
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

        signature = private_key.sign(
            statement.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    return signature


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
        global user_id
        user_id = input(" User Id: ") or "user1"

        # get the user private key filename or default to user1.key
        private_key_filename = input(" Private Key Filename: ") or "user1.key"

        # Get the current working directory
        current_working_directory = os.getcwd()

        # Extract the last part of the path, which should be 'Client1' or 'Client2'
        client_name = os.path.basename(current_working_directory)

        # complete the full path of the user private key filename (depends on the client)
        # Ex: '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename
        user_private_key_file = os.path.join(
            "/home/cs6238/Desktop/Project4",
            client_name,
            "userkeys",
            private_key_filename,
        )

        # create the statement
        statement = "statement"
        signed_statement = sign_statement(statement, user_private_key_file)

        body = {
            "user_id": user_id,
            "statement": statement,
            "signed_statement": base64.b64encode(signed_statement).decode("utf8"),
        }

        server_response = post_request(
            server_name, "login", body, node_certificate, node_key
        )

        if server_response.json().get("status") == 200:
            print("Log in Successful")
            successful_login = True

        elif server_response.json().get("status") == 700:
            print("Log in Failed")

    return server_response.json()


def checkin(session_token):
    """
    # TODO: Accept the
     - DID: document id (filename)
     - security flag (1 for confidentiality  and 2 for integrity)
    Send the request to server with required parameters (action = 'checkin') using post_request().
    The request body should contain the required parameters to ensure the file is sent to the server.
    """

    try:
        security_flag = int(
            input("Please enter a flag (1 for confidentiality, 2 for integrity): ")
        )
        if security_flag not in [1, 2]:
            print("Invalid input. Please enter either 1 or 2.")
            exit()
    except ValueError:
        print("Invalid input. Please use numeric values.")
        exit()

    # Get the current working directory
    current_working_directory = os.getcwd()

    # Extract the last part of the path, which should be 'Client1' or 'Client2'
    client_name = os.path.basename(current_working_directory)

    # Get document ID from user
    file_name = input("Please enter the file name: ")
    client_checkin_file_path = os.path.join(
        "/home/cs6238/Desktop/Project4",
        client_name,
        "documents/checkin",
        file_name,
    )

    if not os.path.isfile(client_checkin_file_path):
        print(
            f"File not found at {client_checkin_file_path}. Please check the filename and try again."
        )
        exit()

    # Read file content
    try:
        with open(client_checkin_file_path, "rb") as file:
            file_data = file.read()
    except IOError as e:
        print(f"Error reading file {client_checkin_file_path}: {e}")
        exit()

    # Encode file_data with base64 before putting it into the body
    encoded_file_data = base64.b64encode(file_data).decode("utf-8")

    body = {
        "security_flag": security_flag,
        "document_id": file_name,
        "file_data": encoded_file_data,
        "session_token": session_token,
        "user_id": user_id,
    }

    server_response = post_request(
        server_name,
        "checkin",
        body,
        node_certificate,
        node_key,
    )

    if server_response.json().get("status") == 200:
        print("Document Successfully checked in")

    elif server_response.json().get("status") == 702:
        print("Access denied checking in")

    elif server_response.json().get("status") == 700:
        print("Other errors")

    return server_response.json()


def checkout(session_token):
    """
    Send request to server with required parameters (action = 'checkout') using post_request()
    """
    # Get document ID from user
    file_name = input("Please enter the file name: ")

    # Get the current working directory
    current_working_directory = os.getcwd()

    # Extract the last part of the path, which should be 'Client1' or 'Client2'
    client_name = os.path.basename(current_working_directory)

    body = {
        "document_id": file_name,
        "user_id": user_id,
        "session_token": session_token,
        "client_name": client_name,
    }
    server_response = post_request(
        server_name, "checkout", body, node_certificate, node_key
    )

    if server_response.json().get("status") == 200:
        print("Document Successfully checked out")

    elif server_response.json().get("status") == 702:
        print("Access denied checking out")

    elif server_response.json().get("status") == 703:
        print("Check out failed due to broken integrity")

    elif server_response.json().get("status") == 704:
        print("Check out failed since file not found on the server")

    elif server_response.json().get("status") == 700:
        print("Other failures")

    return server_response.json()


def grant(session_token):
    """
    # TODO:
     - DID
     - target user to whom access should be granted (0 for all user)
     - type of access to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
     - time duration (in seconds) for which access is granted
    Send request to server with required parameters (action = 'grant') using post_request()
    """
    # Get document ID from user
    file_name = input("Please enter the file name: ")

    print("Grant Permission Options:")
    print("1 = Checkin")
    print("2 = Checkout")
    print("3 = Checkin + Checkout")
    grant_code = input("Please input grant permission number: ")
    user_grant = input("Please input user to grant to: ")
    user_timer = input("Please input permission time to live: ")

    body = {
        "document_id": file_name,
        "user_id": user_id,
        "grant_code": grant_code,
        "user_grant": user_grant,
        "session_token": session_token,
        "user_timer": user_timer,
    }

    server_response = post_request(
        server_name, "grant", body, node_certificate, node_key
    )

    if server_response.json().get("status") == 200:
        print("Successfully granted access")

    elif server_response.json().get("status") == 702:
        print("Access denied to grant access")

    elif server_response.json().get("status") == 700:
        print("Other failures")

    return server_response.json()


def delete(session_token):
    """
    # TODO:
    Send request to server with required parameters (action = 'delete')
    using post_request().
    """
    file_name = input("Please enter file name to delete: ")
    body = {
        "document_id": file_name,
        "user_id": user_id,
        "session_token": session_token,
    }

    server_response = post_request(
        server_name, "delete", body, node_certificate, node_key
    )

    if server_response.json().get("status") == 200:
        print("Successfully deleted the file")

    elif server_response.json().get("status") == 702:
        print("Access denied deleting file")

    elif server_response.json().get("status") == 704:
        print("File or metadata not found on the server")

    elif server_response.json().get("status") == 700:

        print("Other failures")

    return server_response.json()


def logout(session_token):
    """
    # TODO: Ensure all the modified checked out documents are checked back in.
    Send request to server with required parameters (action = 'logout') using post_request()
    The request body should contain the user-id, session-token
    """
    body = {
        "user_id": user_id,
        "session_token": session_token,
    }

    server_response = post_request(
        server_name, "logout", body, node_certificate, node_key
    )

    if server_response.json().get("status") == 200:
        print("Successfully Logged out")

    elif server_response.json().get("status") == 700:
        print("Failed to log out")

    return server_response.json()


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
