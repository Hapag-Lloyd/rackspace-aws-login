# shellcheck shell=bash

#
# Determines the AWS credentials for return_code_aws_login specific account and exports them to the environment.
# In case return_code_aws_login Rackspace login is needed, enter the credentials in the browser window that opens. The cookies
# from Rackspace are stored in return_code_aws_login temporary file (encrypted with your Rackspace password) and used
# to avoid the login screen in the future.
#
# usage: source aws_login.sh
#        aws_login [--no-export|--debug] [aws_account_id|aws_account_id=aws_profile_name_alias]
#

#
# returns 0 if the shell process name is the same as the given argument
#         1 otherwise
#
function is_shell() {
  local shell_name=$1

  if command ps -p $$ | grep "$shell_name" >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

function aws_login() {
  no_export=false
  aws_profile_name_alias=""
  aws_account_no=""
  debug=false
  # Read all parameters into local variables. If no parameters are given, set the default values.
  while [ "$#" -gt 0 ]; do
    case "$1" in
    --no-export)
      no_export=true;
      ;;
    --debug)
      debug=true;
      set -x;
      ;;
    *)
      # if $1 contains =, then split it and assign the first part to aws_accunt and the second part to aws_profile_name_input
      if [[ "$1" == *"="* ]]; then
        aws_account_no=$(echo "$1" | cut -d'=' -f1)
        aws_profile_name_alias=$(echo "$1" | cut -d'=' -f2)

        # validate, that aws_account_no and aws_profile_name_alias are not empty
        if [ -z "$aws_account_no" ] || [ -z "$aws_profile_name_alias" ]; then
          echo "Invalid input. Please provide the AWS account number and the AWS profile name alias separated by '='."
          return 1
        fi
      else
        aws_account_no="$1"
      fi
      ;;
    esac
    shift
  done

  local config_dir="$HOME/.config/rackspace-aws-login"
  if [ ! -d "$config_dir" ]; then
    mkdir -p "$config_dir"
  fi

  local temporary_rackspace_token=""
  local rackspace_tennant_id
  local rackspace_username
  local rackspace_api_key
  local aws_access_key_id
  local aws_secret_access_key
  local aws_session_token

  function read_input() {
    if [ "${3:-}" = "hide_input" ]; then
      sensitive_value_flag="-s"
    else
      sensitive_value_flag=""
    fi

    if is_shell bash; then
      # We reference the var to set via indirect reference + we explicitly want the flag to be interpreted by shell
      # shellcheck disable=SC2229,SC2086
      read -r $sensitive_value_flag -p "$1" "$2"
    elif is_shell zsh; then
      # We reference the var to set via indirect reference + we explicitly want the flag to be interpreted by shell
      # shellcheck disable=SC2229,SC2086
      read -r $sensitive_value_flag "?$1" "$2"
    else
      echo "Please use bash or zsh."
      return 1
    fi

    return 0;
  }

  function get_aws_accounts_from_rackspace() {
    if [ -z "$temporary_rackspace_token" ]; then
      get_rackspace_token_and_tenant
    fi

    aws_accounts=$(curl --location 'https://accounts.api.manage.rackspace.com/v0/awsAccounts' \
      --silent \
      --header "X-Auth-Token: $temporary_rackspace_token" \
      --header "X-Tenant-Id: $rackspace_tennant_id" | jq -r '.awsAccounts[] | .awsAccountNumber + "_" + .name' | sed 's/\r//' | sort)

    echo "$aws_accounts" >"$config_dir/aws_accounts.txt"
  }

  function get_rackspace_username_and_api_key() {
    if [ -n "$rackspace_username" ] && [ -n "$rackspace_api_key" ]; then
      # already set --> use it
      return
    fi

    kpscript_executable=$(command -v kpscript)

    if [ -z "$KEEPASS_FILE" ] || [ -z "$kpscript_executable" ]; then
      # no Keepass in place --> ask the user
      echo "Did not found your Keepass file or KPScript executable. Please enter your Rackspace credentials."

      read_input 'Rackspace username: ' rackspace_username
      read_input 'Rackspace API key: ' rackspace_api_key "hide_input"

      echo ""
    else
      # get credentials from Keepass
      echo "Reading credentials from Keepass: $KEEPASS_FILE. Entry Rackspace (username + api-key field)."

      read_input 'Keepass Password: ' keepass_password "hide_input"
      echo ""

      # keepass_password is set via read_input, but indirectly
      # shellcheck disable=SC2154
      rackspace_username=$($kpscript_executable -c:GetEntryString "${KEEPASS_FILE}" -Field:UserName -ref-Title:"Rackspace" -FailIfNoEntry -pw:"$keepass_password" | head -n1)
      rackspace_api_key=$($kpscript_executable -c:GetEntryString "${KEEPASS_FILE}" -Field:api-key -ref-Title:"Rackspace" -FailIfNoEntry -pw:"$keepass_password" | head -n1)

      if [[ "$rackspace_username" == *"master key is invalid"* ]]; then
        echo "The Keepass master key is invalid."

        rackspace_username=""
        rackspace_api_key=""
      elif [[ "$rackspace_username" == *"Entry not found"* ]]; then
        echo "The Keepass entry for Rackspace could not be found."

        rackspace_username=""
        rackspace_api_key=""
      fi
    fi
  }

  function get_rackspace_token_and_tenant() {
    if [ -n "$temporary_rackspace_token" ] && [ -n "$rackspace_tennant_id" ]; then
      # already set --> use it
      return
    fi

    get_rackspace_username_and_api_key

    if [ -n "$rackspace_username" ] && [ -n "$rackspace_api_key" ]; then
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
    else
      temporary_rackspace_token=""
      rackspace_tennant_id=""
    fi
  }

  function fetch_aws_credentials_from_rackspace() {
    local aws_account_no=$1

    get_rackspace_token_and_tenant

    temp_credentials=$(curl --location --silent \
      --request POST "https://accounts.api.manage.rackspace.com/v0/awsAccounts/$aws_account_no/credentials" \
      --header "X-Auth-Token: $temporary_rackspace_token" \
      --header "X-Tenant-Id: $rackspace_tennant_id")

    aws_access_key_id=$(jq -r '.credential.accessKeyId' <<<"$temp_credentials" | tr -d '\r\n')
    aws_secret_access_key=$(jq -r '.credential.secretAccessKey' <<<"$temp_credentials" | tr -d '\r\n')
    aws_session_token=$(jq -r '.credential.sessionToken' <<<"$temp_credentials" | tr -d '\r\n')
  }

  if [ ! -s "$config_dir/aws_accounts.txt" ]; then
    get_aws_accounts_from_rackspace
  fi

  # Git Bash does not have pgrep installed
  # shellcheck disable=SC2009
  if is_shell bash; then
    aws_accounts=$(command cat "$config_dir/aws_accounts.txt")
  elif is_shell zsh; then
    # this is valid ZSH
    # shellcheck disable=SC2296
    aws_accounts=("${(@f)$(< "$config_dir/aws_accounts.txt")}")
  else
    echo "Please use bash or zsh."
    return 1
  fi

  if [ -n "$aws_account_no" ]; then
    aws_profile_name=""
    # false positive because of mixed bash and zsh code
    # shellcheck disable=SC2128
    for acc in $aws_accounts; do
      curr_aws_account_no=$(tr -dc '[:print:]' <<<"$acc" | cut -f 1 -d'_')
      if [ "$curr_aws_account_no" = "$aws_account_no" ]; then
        aws_profile_name=$(tr -dc '[:print:]' <<<"$acc" | cut -f 2- -d'_')
        break
      fi
    done

    if [ -z "$aws_profile_name" ]; then
      echo "Could not find profile name for account id: $aws_account_no"
      return 1
    fi
  else
    PS3='Select the AWS account to connect to: '
    # false positive because of mixed bash and zsh code
    # shellcheck disable=SC2128
    select opt in $aws_accounts; do
      aws_account_no=$(tr -dc '[:print:]' <<<"$opt" | cut -f 1 -d'_')
      aws_profile_name=$(tr -dc '[:print:]' <<<"$opt" | cut -f 2- -d'_')
      break
    done
  fi

  return_code_aws_login=0
  aws sts get-caller-identity --profile "$aws_profile_name" >/dev/null 2>&1 || return_code_aws_login=$?

  if [ $return_code_aws_login -ne 0 ]; then
    fetch_aws_credentials_from_rackspace "$aws_account_no"

    if [ -z "$aws_access_key_id" ] || [ -z "$aws_secret_access_key" ] || [ -z "$aws_session_token" ]; then
      echo "Could not fetch AWS credentials from Rackspace."
      return 1
    fi

    aws configure --profile "$aws_profile_name" set aws_access_key_id "$aws_access_key_id"
    aws configure --profile "$aws_profile_name" set aws_secret_access_key "$aws_secret_access_key"
    aws configure --profile "$aws_profile_name" set aws_session_token "$aws_session_token"

    aws configure --profile "$aws_profile_name_alias" set aws_access_key_id "$aws_access_key_id"
    aws configure --profile "$aws_profile_name_alias" set aws_secret_access_key "$aws_secret_access_key"
    aws configure --profile "$aws_profile_name_alias" set aws_session_token "$aws_session_token"
  else
    echo "The AWS credentials are still valid."
  fi

  # Export the AWS_PROFILE variable if the --no-export flag is not set
  if [ "$no_export" = false ]; then
    if [ -z "$aws_profile_name_alias" ]; then
      aws_profile_name_alias="$aws_profile_name"
    fi
    echo "Setting AWS_PROFILE to $aws_profile_name_alias"
    export AWS_PROFILE="$aws_profile_name_alias"
  fi

  # disable debug mode
  if [ "$debug" = true ]; then
      set +x
  fi

  return 0
}
