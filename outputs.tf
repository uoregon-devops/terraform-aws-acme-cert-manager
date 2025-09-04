output "cert_manager_function_name" {
  value       = aws_lambda_function.cert-manager.function_name
  description = "Name of the lambda function for cert enrollment invocation. Keep in mind that the lambda and dynamoDB table are provisioned in the providers set region, so when you invoke the lambda function, the provider doing it must be in the correct region."
}

output "cert_manager_credentials_secret_name" {
  value = data.aws_secretsmanager_secret.cert_manager_credentials.name
}
