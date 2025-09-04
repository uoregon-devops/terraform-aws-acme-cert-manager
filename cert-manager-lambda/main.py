# lambda function to write to a DynamoDB table
import json
import boto3
import os
import sys

# add the 'packages' directory to sys.path
packages_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'packages')
sys.path.append(packages_dir)

from certbot import main
import acme

cert_manager_table_name = os.environ['CERT_MANAGER_TABLE_NAME']
acme_credentials_secret_arn = os.environ['ACME_CREDENTIALS_SECRET_ARN']
acme_server_url = os.environ['ACME_SERVER_URL']
certificate_enrollment_email = os.environ['ENROLLMENT_EMAIL_CONTACT']

dynamodb = boto3.resource('dynamodb')
secrets_manager = boto3.client('secretsmanager')

def obtain_certificate(domains, email, acme_server, eab_key_id, eab_key):
    print(f"Attempting to obtain a certificate for {domains[0]}...")

    cli_config =  "\n".join([
        f"domains = {','.join(domains)}",
        f"email = {email}",
        f"server = {acme_server}",
        f"eab-kid = {eab_key_id}",
        f"eab-hmac-key = {eab_key}",
        "agree-tos = true",
    ])

    # write the cli_config to a file
    with open('/tmp/cli_config.ini', 'w') as f:
        f.write(cli_config)

    # Translate command-line flags to a list of strings
    certbot_args = [
        'certonly',
        '--standalone',
        '--noninteractive',
        '-c', '/tmp/cli_config.ini',
        '--cert-path', '/tmp',
        '--key-path', '/tmp',
        '--fullchain-path', '/tmp',
        '--chain-path', '/tmp',
        '--logs-dir', '/tmp',
        '--work-dir', '/tmp',
        '--config-dir', '/tmp',
    ]

    try:
        main.main(certbot_args)
        print(f"Successfully obtained certificate for {domains[0]}.")

    except acme.errors.Error as e:
        print(f"An error occurred: {e.error}")
        raise

    cert_path = f"/tmp/live/{domains[0]}/cert.pem"
    key_path = f"/tmp/live/{domains[0]}/privkey.pem"
    chain_path = f"/tmp/live/{domains[0]}/chain.pem"
    fullchain_path = f"/tmp/live/{domains[0]}/fullchain.pem"

    # make a dictionary of content of each file
    content_dict = {
        'cert': open(cert_path, 'rb').read(),
        'key': open(key_path, 'rb').read(),
        'chain': open(chain_path, 'rb').read(),
        'fullchain': open(fullchain_path, 'rb').read()
    }

    return content_dict

def handle_terraform_create(certificate):
    # Extract certificate details from certificate event
    regions = certificate['regions']
    domains = certificate['domains']
    common_name = domains[0]

    cert_table = dynamodb.Table(cert_manager_table_name)

    existing_table_item_response = cert_table.get_item(Key={'common_name': common_name})

    if 'Item' in existing_table_item_response:
        raise Exception(f"Certificate for {common_name} is already managed.")

    # Retrieve ACME credentials from Secrets Manager
    acme_credentials = secrets_manager.get_secret_value(SecretId=acme_credentials_secret_arn)['SecretString']
    try:
        acme_credentials = json.loads(acme_credentials)
    except:
        print("Error decoding ACME credentials, please check that the secret is formatted correctly")
        raise

    eab_key_id = acme_credentials['eab_key_id']
    eab_key = acme_credentials['eab_key']

    enrolled_cert_data = obtain_certificate(domains, certificate_enrollment_email, acme_server_url, eab_key_id, eab_key)


    acm_arns = {}

    for region in regions:
        acm = boto3.client('acm', region_name=region)
        acm_response = acm.import_certificate(
            Certificate=enrolled_cert_data['cert'],
            PrivateKey=enrolled_cert_data['key'],
            CertificateChain=enrolled_cert_data['chain'],
        )
        acm_arns[region] = acm_response['CertificateArn']

    cert_data = {
        'common_name': common_name,
        'domains': domains,
        'certificate_arns': acm_arns,
    }

    # Write certificate details to DynamoDB table
    cert_table.put_item(
        Item=cert_data
    )

    return {
        'statusCode': 200,
        'body': json.dumps(cert_data)
    }

def handle_terraform_update(certificate, previous_certificate):
    # Extract certificate details from certificate event
    regions = certificate['regions']
    domains = certificate['domains']
    common_name = domains[0]

    previous_regions = previous_certificate['regions']
    previous_domains = previous_certificate['domains']
    previous_common_name = previous_domains[0]

    cert_table = dynamodb.Table(cert_manager_table_name)

    existing_table_item_response = cert_table.get_item(Key={'common_name': common_name})

    item = existing_table_item_response['Item']

    # handle if item is missing
    # if not 'Item' in existing_table_item_response:
    #     raise Exception(f"Certificate for {common_name} is already managed.")

    new_domains = [ domain for domain in domains if not domain in previous_domains ]
    removed_domains = [ domain for domain in previous_domains if not domain in domains ]

    if len(domains) != len(previous_domains):
        # Retrieve ACME credentials from Secrets Manager
        acme_credentials = secrets_manager.get_secret_value(SecretId=acme_credentials_secret_arn)['SecretString']
        try:
            acme_credentials = json.loads(acme_credentials)
        except:
            print("Error decoding ACME credentials, please check that the secret is formatted correctly")
            raise

        eab_key_id = acme_credentials['eab_key_id']
        eab_key = acme_credentials['eab_key']

        enrolled_cert_data = obtain_certificate(domains, certificate_enrollment_email, acme_server_url, eab_key_id, eab_key)

        acm_arns = {}

        for region, cert_arn in item['certificate_arns'].items():
            acm = boto3.client('acm', region_name=region)
            acm_response = acm.import_certificate(
                CertificateArn=cert_arn,
                Certificate=enrolled_cert_data['cert'],
                PrivateKey=enrolled_cert_data['key'],
                CertificateChain=enrolled_cert_data['chain'],
            )
            acm_arns[region] = acm_response['CertificateArn']

        cert_data = {
            'common_name': common_name,
            'domains': domains,
            'certificate_arns': acm_arns,
        }

        # Write certificate details to DynamoDB table
        cert_table.put_item(
            Item=cert_data
        )

        return {
            'statusCode': 200,
            'body': json.dumps(cert_data)
        }

def handle_terraform_delete(certificate):
    pass

def handle_terraform_certificate_request(event):
    # Extract supplemental Terraform details
    terraform_details = event['tf']
    terraform_action = terraform_details['action']

    match terraform_action:
        case 'create':
            return handle_terraform_create(event['certificate'])
        case 'update':
            return handle_terraform_update(event['certificate'], terraform_details['prev_input']['certificate'])
        case 'delete':
            handle_terraform_delete(event['certificate'])
        case _:
            raise ValueError(f"Invalid Terraform action: {terraform_action}")

def handle_certificate_renewal_check(event):
    pass

def handler(event, context):
    event_type = None
    if "tf" in event and "certificate" in event:
        print("Handling Terraform certificate event.")
        event_type = "certificate_request"
    elif "renewal_check" in event and event["renewal_check"] == True:
        event_type = "renewal_check"
        print("Handling certificate renewal check.")
    else:
        raise ValueError("Invalid event, this function is only designed to handle Terraform certificate events and certificate renewal checks.")

    match event_type:
        case "certificate_request":
            return handle_terraform_certificate_request(event)
        case "renewal_check":
            return handle_certificate_renewal_check(event)
