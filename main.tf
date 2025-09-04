# handle secret store
locals {
  managed_secrets         = var.acme_credentials_secret_arn == "" ? ["managed_secret"] : []
  cert_manager_secret_arn = var.acme_credentials_secret_arn == "" ? aws_secretsmanager_secret.managed_secrets["managed_secret"].arn : var.acme_credentials_secret_arn
}

resource "aws_secretsmanager_secret" "managed_secrets" {
  for_each = toset(local.managed_secrets)
  name     = "${var.certificate_root_domain}_cert_manager_secrets_${each.key}"
}

data "aws_secretsmanager_secret" "cert_manager_credentials" {
  arn = local.cert_manager_secret_arn
}

# IAM role for Lambda execution
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cert-manager" {
  name               = "cert-manager-lambda-execution-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Package the Lambda function code
data "archive_file" "cert-manager" {
  type        = "zip"
  source_dir  = "${path.module}/cert-manager-lambda"
  output_path = "${path.module}/cert-manager-lambda.zip"
}

locals {
  lambda_safe_root_domain_name = replace(var.certificate_root_domain, ".", "_")
}

# Lambda function
resource "aws_lambda_function" "cert-manager" {
  function_name = "${local.lambda_safe_root_domain_name}_cert-manager"
  role          = aws_iam_role.cert-manager.arn

  filename         = data.archive_file.cert-manager.output_path
  source_code_hash = data.archive_file.cert-manager.output_base64sha256
  handler          = "main.handler"
  runtime          = "python3.12"

  timeout = 120

  environment {
    variables = {
      CERT_MANAGER_TABLE_NAME     = aws_dynamodb_table.certificates.name
      ACME_CREDENTIALS_SECRET_ARN = local.cert_manager_secret_arn
      ENROLLMENT_EMAIL_CONTACT    = var.certificate_enrollment_contact_email
      ACME_SERVER_URL             = var.acme_server_url
    }
  }
}

# dynamodb table to store cert mapping info
resource "aws_dynamodb_table" "certificates" {
  name         = "${var.certificate_root_domain}_cert-manager-certificates"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "common_name"

  attribute {
    name = "common_name"
    type = "S"
  }
}

# This policy defines the specific actions the Lambda function can perform on the DynamoDB table and Secret Manager.
resource "aws_iam_policy" "lambda_dynamodb_policy" {
  name        = "lambda_dynamodb_read_write_policy"
  description = "Allows Lambda to read and write to a specific DynamoDB table"

  # The policy document in JSON format.
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ],
        Effect = "Allow",
        # Important: Restrict this policy to the specific table's ARN
        Resource = aws_dynamodb_table.certificates.arn
      },
      {
        "Effect" : "Allow",
        "Action" : "secretsmanager:GetSecretValue",
        "Resource" : local.cert_manager_secret_arn
      },
      {
        # It's also a good practice to allow logging for the Lambda function
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Attach dynamodb access policy to lambda role
resource "aws_iam_role_policy_attachment" "lambda_dynamodb" {
  role       = aws_iam_role.cert-manager.name
  policy_arn = aws_iam_policy.lambda_dynamodb_policy.arn
}

# Attach ACM access policy to lambda role
resource "aws_iam_role_policy_attachment" "lambda_acm" {
  role       = aws_iam_role.cert-manager.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCertificateManagerFullAccess"
}
