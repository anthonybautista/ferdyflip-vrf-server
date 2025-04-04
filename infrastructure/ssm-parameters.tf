# SSM Parameters for non-sensitive configuration
resource "aws_ssm_parameter" "chain_id" {
  name        = "/fulfillment/CHAIN_ID"
  description = "The chain ID, e.g. 132008 for bitcoinL1"
  type        = "String"
  value       = var.chain_id
  overwrite   = true
}

resource "aws_ssm_parameter" "vrf_address" {
  name        = "/fulfillment/VRF_ADDRESS"
  description = "The address of the deployed VRFCoordinator for the chain"
  type        = "String"
  value       = var.vrf_address
  overwrite   = true
}

resource "aws_ssm_parameter" "alert_hook_url" {
  name        = "/fulfillment/ALERT_HOOK_URL"
  description = "Discord webhook URL where important alerts are sent"
  type        = "SecureString"
  value       = var.alert_hook_url
  overwrite   = true
}

resource "aws_ssm_parameter" "fulfillment_hook_url" {
  name        = "/fulfillment/FULFILLMENT_HOOK_URL"
  description = "Discord webhook URL where fulfillment info events are sent"
  type        = "SecureString"
  value       = var.fulfillment_hook_url
  overwrite   = true
}

# Secrets Manager for sensitive configuration
resource "aws_secretsmanager_secret" "obfuscated_key" {
  name                    = "fulfillment/OBFUSCATED_KEY"
  description             = "The obfuscated private key for blockchain operations"
  recovery_window_in_days = 0 # Set to 0 for easier testing, consider 7-30 for production
}

resource "aws_secretsmanager_secret_version" "obfuscated_key_value" {
  secret_id     = aws_secretsmanager_secret.obfuscated_key.id
  secret_string = jsonencode({
    key = var.obfuscated_key
  })
}