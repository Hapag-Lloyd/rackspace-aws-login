# rackspace-aws-login

Shell script to fetch credentials for AWS accounts from Rackspace, storing them in AWS profiles. It uses the official
Rackspace API.

Main features:

- fetch AWS credentials from Rackspace API
- fetch new credentials only if old ones are expired or not present
- use AWS profiles via `aws configure`
- list all AWS accounts you are authorized to
- supports Keepass for storing the Rackspace username and API key

## Installation

The minimum requirements are the AWS CLI and [JQ](https://github.com/jqlang/jq). Install them first.

## KeePass support

Create a new entry in your KeePass database with the following fields:

- title: Rackspace
- username: your Rackspace username
- add a custom field with the name `api-key` and the value of your Rackspace API key

Set the path to your KeePass database in the environment variable `KEEPASS_FILE`.

```bash
export KEEPASS_FILE="$HOME/keepass.kdbx"
```

## Usage

Execute `aws_login` on the command line. The first time, the script creates a file in
`$HOME/.config/rackspace-aws-login/aws_accounts.txt` caching your accounts. Remove the file to reset the accounts.

In case the script retrieves the credentials from Rackspace, it asks for the Rackspace username and API key. Check your
Rackspace account to set up the API key. You can put both in a KeePass database and the script will fetch them from there.

```bash
# place this in your .bash_profile
source ./aws_login.sh

# log into an AWS account. The script presents a lists of all accounts
aws_login

# AWS_PROFILE is now set
export | grep AWS_

# list all S3 buckets in the account
aws s3 ls
```

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) and [code of conduct](.github/CODE_OF_CONDUCT.md) for details on our, and
the process for submitting pull requests.
