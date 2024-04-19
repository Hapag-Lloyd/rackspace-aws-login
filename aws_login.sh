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
  local script_dir
  script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

  # $1: optional, AWS account ID to connect to
  local aws_account_id="${1:-}"

  if [ "$(uname)" == "Darwin" ]; then
    source "$script_dir/venv/bin/activate"
  else
    source "$script_dir/venv/Scripts/activate"
  fi

  # credentials are stored in a file as we can't use a subshell (stdout is shown too late in the terminal)
  exit_state=0
  temp_file="$script_dir/aws_temp"
  touch "$temp_file"

  "$script_dir"/get_aws_credentials.py "$temp_file" "$aws_account_id" || exit_state=$?

  deactivate

  aws_credentials_as_json=$(cat "$temp_file")

  rm -f "$temp_file"

  # exit state = 2 --> credentials already present
  if [ $exit_state -eq 2 ]; then
    read -r profile_name < <(echo "$aws_credentials_as_json" | jq -r '.aws_profile_name' | tr -d '\r\n')

    echo "Switching the AWS_PROFILE to $profile_name"
    export AWS_PROFILE="$profile_name"

    return 0
  fi

  if [ $exit_state -ne 0 ]; then
    echo "Failed to get the AWS credentials"

    return 1
  else
    # SC2005: for some reason we need to "echo" here, otherwise the variables are not set
    # SC2046: we need to split the variables here
    # shellcheck disable=SC2005,SC2046
    read -r access_key secret_key session_token profile_name < \
      <(echo $(echo "$aws_credentials_as_json" | jq -r '.aws_access_key_id, .aws_secret_access_key, .aws_session_token, .aws_profile_name'))

    echo "Switching the AWS_PROFILE to $profile_name and setting the credentials"

    aws configure --profile "$profile_name" set aws_access_key_id "$(echo "$access_key" | tr -d '\r\n')"
    aws configure --profile "$profile_name" set aws_secret_access_key "$(echo "$secret_key" | tr -d '\r\n')"
    aws configure --profile "$profile_name" set aws_session_token "$(echo "$session_token" | tr -d '\r\n')"

    export AWS_PROFILE="$profile_name"

    return 0
  fi
}
