# rackspace-aws-login

Shell script to fetch credentials for AWS accounts from Rackspace, storing them in AWS profiles. It uses the official
Rackspace API.

Main features:

- fetch AWS credentials from Rackspace
- fetch new credentials only if old ones are expired or not present
- use AWS profiles via `aws configure`
- list all AWS accounts you are authorized to

## Installation

The minimum requirements are the AWS CLI and [JQ](https://github.com/jqlang/jq). Install them first.

## Usage

Execute `aws_login` on the command line. The first time, the script creates a file in
`$HOME/config/rackspace-aws-login/aws_accounts.json` caching your accounts. Remove the file to reset the accounts.

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
