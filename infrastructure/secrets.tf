variable "chain_id" {
  description = "The chain ID, e.g. 132008 for bitcoinL1"
  type        = number
}

variable "obfuscated_key" {
  description = "The obfuscated private key, see utils/keys.py for more details"
  type        = string
  sensitive   = true
}

variable "vrf_address" {
  description = "The address of the deployed VRFCoordinator for the chain"
  type        = string
}

variable "alert_hook_url" {
  description = "Discord webhook URL where important alerts are sent"
  type        = string
  sensitive   = true
}

variable "fulfillment_hook_url" {
  description = "Discord webhook URL where fulfillment info events are sent"
  type        = string
  sensitive   = true
}
