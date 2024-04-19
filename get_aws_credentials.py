#!/usr/bin/env python

#
# Creates a menu to select an AWS account and fetches the AWS credentials from Rackspace. The credentials are
# printed as json to stdout. Format: {"aws_access_key_id": "AKIA...", "aws_secret_access_key": "...",
#                                     "aws_session_token": "...", "aws_profile_name": "xyz"}
#
# $1 optional, AWS account id, skips the menu
#
# Exit states:
# 0 - success, credentials returned in file
# 1 - error, no credentials returned. Check output for details.
# 2 - already authenticated with AWS. Outputs the profile name as json.
#

import boto3
import json
import os
import secrets
import subprocess
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pathlib import Path

from playwright.sync_api import sync_playwright, Page, BrowserContext

CONFIG_PATH = f"{os.getenv('HOME')}/.config/rackspace-aws-login"
COOKIE_FILE = f"{CONFIG_PATH}/rackspace_cookies.enc"
DEFAULT_AWS_ACCOUNTS_FILE = f"{CONFIG_PATH}/aws_accounts.json"
USER_AWS_ACCOUNTS_FILE = f"{CONFIG_PATH}/aws_accounts_user.json"

RACKSPACE_AWS_ACCOUNT_URL_PREFIX = "https://manage.rackspace.com/aws/accounts"
RACKSPACE_TIMEOUT_MS = 60000


def get_aws_account_info(preselected_account_number: str | None) -> dict[str, str] | None:
    if Path(USER_AWS_ACCOUNTS_FILE).exists():
        aws_accounts = json.loads(Path(USER_AWS_ACCOUNTS_FILE).read_text().replace('\n', ''))['aws_accounts']
    else:
        aws_accounts = json.loads(Path(DEFAULT_AWS_ACCOUNTS_FILE).read_text().replace('\n', ''))['aws_accounts']

    if preselected_account_number:
        for aws_account in aws_accounts:
            if aws_account['number'] == preselected_account_number:
                return aws_account

        print("AWS account not found.")

        return None
    else:
        for index, aws_account in enumerate(aws_accounts, start=1):
            print(f"{index:2}. {aws_account['number']:12} - {aws_account['name']}")

        choice = input("Select an AWS account: ")
        try:
            choice = int(choice)
            if 1 <= choice <= len(aws_accounts):
                return aws_accounts[choice - 1]
            else:
                print("Invalid choice. Please enter a valid number.")
                return get_aws_account_info(None)
        except ValueError:
            print("Invalid input. Please enter a number.")
            return get_aws_account_info(None)


def get_password(prompt: str) -> str:
    print(prompt, end="", flush=True)

    # don't echo the password
    subprocess.check_call(["stty", "-echo"])
    password = input()
    subprocess.check_call(["stty", "echo"])

    # print a \n to move the cursor to the next line
    print()

    return password


def generate_aes_key_from_password(password: str) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES
        salt=b"no-salt-at-all",
        iterations=100000,
        backend=default_backend()
    ).derive(password.encode())


def write_encrypted_file(filename: str, plaintext: str, password: str):
    key = generate_aes_key_from_password(password)
    nonce = secrets.token_bytes(12)
    ciphertext = nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), b"")

    Path(filename).write_bytes(ciphertext)


def decrypt_from_file(filename: str, password: str) -> str:
    key = generate_aes_key_from_password(password)
    ciphertext = Path(filename).read_bytes()

    try:
        return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], b"").decode()
    except Exception:
        # decryption failed (usually due to changed password). File is deleted, nothing returned
        Path(filename).unlink()
        return '[]'


def rackspace_login(password: str, aws_account_number: str, page: Page, context: BrowserContext):
    # login to be done manually by user
    page.bring_to_front()

    # pre-fill the password, we know it already
    page.fill('input[id="password"]', password)
    page.click('input[id="username"]')

    # wait for user input, disable the default timeout
    page.wait_for_url(f"{RACKSPACE_AWS_ACCOUNT_URL_PREFIX}/{aws_account_number}", timeout=0)

    write_cookies_to_file(context, password)


def write_cookies_to_file(context: BrowserContext, password: str):
    write_encrypted_file(COOKIE_FILE, json.dumps(context.cookies()), password)


def check_current_aws_credentials_valid_for_account(aws_account_number: str, profile_name: str) -> bool:
    try:
        # use the AWS profile for the client to avoid using the default profile
        session = boto3.session.Session(profile_name=profile_name)
        identity = session.client("sts").get_caller_identity()

        return identity['Account'] == aws_account_number
    except Exception as e:
        print(e)
        return False


def convert_aws_credentials_to_json(aws_credentials_for_credential_file: str, profile_name: str) -> str:
    # throw away the first line and last line (profile name and a comment)
    aws_credentials = aws_credentials_for_credential_file.split("\n")[1:-1]

    json_return_value = {'aws_profile_name': profile_name}

    for line in aws_credentials:
        key, value = line.split("=", maxsplit=1)
        json_return_value[key] = value

    return json.dumps(json_return_value)


def write_result(filename: str, aws_credentials_json: str):
    Path(filename).write_text(aws_credentials_json)


def get_rackspace_page(url: str, rackspace_password: str, aws_account_number: str, context: BrowserContext)\
        -> Page:
    page = context.new_page()
    page.bring_to_front()

    # restore previous Rackspace session to skip the login procedure and speed up the process
    context.clear_cookies()
    if Path(COOKIE_FILE).exists():
        context.add_cookies(json.loads(decrypt_from_file(COOKIE_FILE, rackspace_password)))

    page.goto(url)

    if page.title() == "Rackspace Login":
        rackspace_login(rackspace_password, aws_account_number, page, context)

    return page


def main(output_filename: str, aws_account_number: str | None):
    selected_aws_account = get_aws_account_info(aws_account_number)

    # exit if no account was selected
    if selected_aws_account is None:
        exit(1)

    aws_profile_name = selected_aws_account['name']
    aws_account_number = selected_aws_account['number']

    print(f"Fetching AWS credentials for account {aws_account_number} ...", flush=True)

    if check_current_aws_credentials_valid_for_account(aws_account_number, aws_profile_name):
        print("AWS credentials still valid. No need to fetch credentials from Rackspace.")

        write_result(output_filename, json.dumps({'aws_profile_name': aws_profile_name}))
        exit(2)

    rackspace_password = get_password("Enter Rackspace password: ")

    print("Please wait, getting the credentials from Rackspace takes some time ...", flush=True)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            context.set_default_timeout(RACKSPACE_TIMEOUT_MS)

            aws_account_page = get_rackspace_page(f"https://manage.rackspace.com/aws/accounts/{aws_account_number}",
                                                  rackspace_password, aws_account_number, context)

            aws_account_page.click("button:has-text(\"Generate Credentials\")")

            aws_account_page.wait_for_selector("a[id=\"temporary-credentials-tabs-tab-AWS_TAB\"]")
            aws_account_page.click('a[id="temporary-credentials-tabs-tab-AWS_TAB"]')

            aws_credential_field_selector = "pre[class=\"ja-code aws-credentials\"]"
            aws_credentials = aws_account_page.text_content(aws_credential_field_selector)

            write_result(output_filename, convert_aws_credentials_to_json(aws_credentials, aws_profile_name))

            # update the cookies in case they have changed
            write_cookies_to_file(context, rackspace_password)
        except Exception as e:
            print(e)
            exit(1)


if __name__ == "__main__":
    aws_credentials_file = sys.argv[1]
    aws_account_no = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].isdigit() else None

    main(aws_credentials_file, aws_account_no)
