
resource "aws_lambda_invocation" "certificate-manager-request" {
  function_name   = var.certificate_manager_function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    certificate = {
      domains = var.domains
      regions = var.regions
    }
  })
}

variable "certificate_manager_function_name" {
  description = "Lambda function name of certificate manager."
  type        = string
}

variable "domains" {
  description = "List of domains, the first beging the common name of the certficate, the rest being the subject alternative names."
  type        = list(string)
}

variable "regions" {
  description = "List of regions to provision ACM certificates in. Each region will result in a \"region_name\":\"certificate_arn\" key:value pair in the output value \"acm_certificate_arns\"."
  type        = list(string)
}

output "acm_certificate_arns" {
  description = "Dictionary with key region and value ACM certificate ARN."
  value       = jsondecode(jsondecode(aws_lambda_invocation.certificate-manager-request.result)["body"])["certificate_arns"]
}
