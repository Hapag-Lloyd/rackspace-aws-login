# shellcheck shell=bash

#
# Determines the AWS credentials for a specific account and exports them to the environment.
# In case a Rackspace login is needed, enter the credentials in the browser window that opens. The cookies
# from Rackspace are stored in a temporary file (encrypted with your Rackspace password) and used
# to avoid the login screen in the future.
#
# usage: source aws_login.sh
#        aws_login [aws_account_id]
#
function aws_login() {
  local config_dir="$HOME/.config/rackspace-aws-login"
  if [ ! -d "$config_dir" ]; then
    mkdir -p "$config_dir"
  fi

  local temporary_rackspace_token
  local rackspace_tennant_id
  local rackspace_username
  local rackspace_api_key

  function get_aws_accounts_from_rackspace() {
    if [ -z "$temporary_rackspace_token" ]; then
      get_rackspace_token_and_tenant
    fi

    aws_accounts=$(curl --location 'https://accounts.api.manage.rackspace.com/v0/awsAccounts' \
      --silent \
      --header "X-Auth-Token: $temporary_rackspace_token" \
      --header "X-Tenant-Id: $rackspace_tennant_id" | jq -r '.awsAccounts[] | .awsAccountNumber + "_" + .name' | sed 's/\r//' | sort)

    echo "$aws_accounts" > "$config_dir/aws_accounts.txt"
  }

  function get_rackspace_username_and_api_key() {
    kpscript_executable=$(command -v kpscript)

    if [ -z "$KEEPASS_FILE" ] || [ -z "$kpscript_executable" ]; then
      # no Keepass in place --> ask the user
      echo "Did not found your Keepass file or KPScript executable. Please enter your Rackspace credentials."

      read -r -p 'Rackspace username: ' rackspace_username
      read -r -sp 'Rackspace API key: ' rackspace_api_key
    else
      # get credentials from Keepass
      echo "Reading credentials from Keepass: $KEEPASS_FILE. Entry Rackspace (username + api-key field)."

      read -r -sp 'Keepass Password: ' keepass_password
      echo ""

      rackspace_username=$($kpscript_executable -c:GetEntryString "${KEEPASS_FILE}" -Field:UserName -ref-Title:"Rackspace" -FailIfNoEntry -pw:"$keepass_password" | head -n1 )
      rackspace_api_key=$($kpscript_executable -c:GetEntryString "${KEEPASS_FILE}" -Field:api-key -ref-Title:"Rackspace" -FailIfNoEntry -pw:"$keepass_password" | head -n1 )
    fi
  }

  function get_rackspace_token_and_tenant() {
    get_rackspace_username_and_api_key

    rackspace_token_json=$(curl --location 'https://identity.api.rackspacecloud.com/v2.0/tokens' \
      --header 'Content-Type: application/json' \
      --silent \
      --data "{
            \"auth\": {
                \"RAX-KSKEY:apiKeyCredentials\": {
                    \"username\": \"$rackspace_username\",
                    \"apiKey\": \"$rackspace_api_key\"
                }
            }
        }")

    temporary_rackspace_token=$(jq -r '.access.token.id' <<<"$rackspace_token_json")
    rackspace_tennant_id=$(jq -r '.access.token.tenant.id' <<<"$rackspace_token_json")
  }

  if [ ! -f "$config_dir/aws_accounts.txt" ]; then
    get_rackspace_token_and_tenant
  fi

  aws_accounts=$(cat "$config_dir/aws_accounts.txt")

  PS3='Select the AWS account to connect to: '
  select opt in $aws_accounts; do
    aws_account_no=$(tr -dc '[:print:]' <<<"$opt" | cut -f 1 -d'_')
    aws_profile_name=$(tr -dc '[:print:]' <<<"$opt" | cut -f 2- -d'_')
    break
  done

  exit_state=0
  aws sts get-caller-identity --profile "$aws_profile_name" >/dev/null 2>&1 || exit_state=$?

  if [ $exit_state -ne 0 ]; then
    if [ -z "$temporary_rackspace_token" ]; then
      get_rackspace_token_and_tenant
    fi

    temp_credentials=$(curl --location --silent \
                        --request POST "https://accounts.api.manage.rackspace.com/v0/awsAccounts/$aws_account_no/credentials" \
                        --header "X-Auth-Token: $temporary_rackspace_token" \
                        --header "X-Tenant-Id: $rackspace_tennant_id")

    access_key=$(jq -r '.credential.accessKeyId' <<<"$temp_credentials")
    secret_access_key=$(jq -r '.credential.secretAccessKey' <<<"$temp_credentials")
    session_token=$(jq -r '.credential.sessionToken' <<<"$temp_credentials")

    aws configure --profile "$aws_profile_name" set aws_access_key_id "$(echo "$access_key" | tr -d '\r\n')"
    aws configure --profile "$aws_profile_name" set aws_secret_access_key "$(echo "$secret_access_key" | tr -d '\r\n')"
    aws configure --profile "$aws_profile_name" set aws_session_token "$(echo "$session_token" | tr -d '\r\n')"
  else
    echo "The AWS credentials are still valid."
  fi

  echo "Switching the AWS_PROFILE to $aws_profile_name"

  export AWS_PROFILE="$aws_profile_name"

  return 0
}
