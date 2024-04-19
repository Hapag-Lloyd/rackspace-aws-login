#!/usr/bin/env bash

function find_python_executable() {
  if command -v python3 &> /dev/null; then
    echo "python3"
  elif command -v python &> /dev/null; then
    echo "python"
  else
    echo "Python missing! Please install Python first."
    exit 1
  fi
}

#
# check requirements
#
if ! command -v pip &> /dev/null; then
  echo "pip is not available. Please install pip first."
  exit 1
fi

python_executable=$(find_python_executable)

#
# install dependencies in a virtual environment
#
"$python_executable" -m venv venv

if [ "$(uname)" == "Darwin" ]; then
  # MacOS

  # external file
  # shellcheck source=/dev/null
  source venv/bin/activate
else
  # external file
  # shellcheck source=/dev/null
  source venv/Scripts/activate
fi

pip install --requirement requirements.txt

playwright install

deactivate

#
# set up the configuration
#
mkdir -p ~/.config/rackspace-aws-login

if [ -f ~/.config/rackspace-aws-login/aws_login.sh ]; then
  echo "aws_login.sh already exists in ~/.config/rackspace-aws-login."
  exit 2
else
  cp aws_login.sh ~/.config/rackspace-aws-login/aws_login.sh
fi
