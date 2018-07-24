# AWS WAF Verification Script
Simple script for AWS WAF verification.

This script throw http request which prepared beforehand automatically to AWS WAF.

## Quick start

You must modify `cf_id` and `TARGET_HOST` variable in `main.py` file.

After that run below command.

    $ python main.py
  

## Configuration

### ~/.aws/config

    [profile dev]
    region = ap-northeast-1

### ~/.aws/credential

    [dev] 
    aws_access_key_id = 
    aws_secret_access_key = 

## Prerequisites

- Python  2.7
- boto3  1.7.29 (or later)
- requests  2.18.4 (or later)

