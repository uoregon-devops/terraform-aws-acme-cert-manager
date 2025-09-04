variable "acme_credentials_secret_arn" {
  type        = string
  default     = ""
  description = "ARN for secret with keys eab_key_id and eab_key key/value pairs. If not provided, a secret will be created."
}

variable "acme_server_url" {
  type        = string
  description = "URL for ACME server."
}

variable "certificate_root_domain" {
  type        = string
  description = "Root domain that this cert manager will use to issue certificates."
}

variable "certificate_enrollment_contact_email" {
  type        = string
  description = "Email address to use for enrolled certificates."
}
