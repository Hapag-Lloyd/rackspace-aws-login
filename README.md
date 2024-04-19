# rackspace-aws-login

Shell and Python scripts to fetch credentials for AWS accounts from Rackspace, storing them in AWS profiles.

Main features:
- fetch AWS credentials from Rackspace
- cache the Rackspace login cookies (encrypted) to speed up subsequent logins
- fetch new credentials only if old ones are expired or not present
- use AWS profiles via `aws configure`
- flexible account setup on user level

## Installation

The minimum requirements are: Python, virtualenv and the AWS CLI. The script expects a `venv` in the same directory. Execute
`install_requirements.sh` to install all other dependencies.

## Usage

Set up your AWS accounts in `~/.config/aws_accounts.json`. The account name is used as the AWS profile name.

```json
{
  "aws_accounts": [
    {
      "number": "123456789012",
      "name": "QA"
    }
  ]
}
```

Execute the login script with the account name as argument or without to list all available accounts.

```bash
# place this in your .bash_profile
source ./aws_login.sh

# log into a AWS account 123456789012
aws_login 123456789012

# AWS_PROFILE is now set
export | grep AWS_

# list all S3 buckets in the account
aws s3 ls
```

# Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.
