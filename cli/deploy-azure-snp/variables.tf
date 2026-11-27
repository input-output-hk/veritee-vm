variable "resource_group_location" {
  type        = string
  default     = "westus"
  description = "Location of the resource group."
}

variable "vm_name" {
  type        = string
  default     = "midnight-mcs-temenos-vm"
  description = "Name of the VM"
}

variable "disk_size" {
  type        = number
  default     = 1000
  description = "size of the os disk"
}

variable "vhd_path" {
  type        = string
  default     = "local-base-os/disk.img.vhd"
  description = "size of the os disk"
}

variable "vhd_sha256" {
  type        = string
  nullable    = false
  description = "Required VHD checksum, verified and supplied by the Veritee CLI. Direct Terraform callers must supply a digest computed from the VHD."
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.vhd_sha256))
    error_message = "vhd_sha256 must be a 64-character lowercase SHA-256 digest."
  }
}

variable "resource_group_name" {
  type        = string
  default     = "midnight-l2-os-rg"
  description = "Exact resource group name for one immutable Veritee deployment."
}

variable "deployment_tags" {
  type        = map(string)
  description = "Operational inventory tags for this immutable Veritee deployment."
}

variable "instance_type" {
  type = string
  //default     = "Standard_NCC40ads_H100_v5"
  default     = "Standard_DC4ads_v5"
  description = "Type/Size of VM to create."
}

variable "gallery_name" {
  type        = string
  default     = "midnight_mcs_image_gallery_"
  description = "Name of the Image Gallery."
}

variable "image_name" {
  type        = string
  default     = "midnight-mcs-os-image"
  description = "Name of the Image."
}

variable "storage_account" {
  type        = string
  default     = "midnightmcsosstorageaccnew"
  description = "Storage account name."
}

variable "storage_container" {
  type        = string
  default     = "midnight-mcs-os-containernew"
  description = "Storage account container name."
}

variable "tls_keyvault_name" {
  type        = string
  default     = ""
  description = "Azure Key Vault name used by azure_vault TLS mode. Empty disables Key Vault role assignment."

  validation {
    condition = var.tls_keyvault_name == "" || (
      can(regex("^[a-z][a-z0-9-]{1,22}[a-z0-9]$", var.tls_keyvault_name))
      && !can(regex("--", var.tls_keyvault_name))
    )
    error_message = "Azure Key Vault name must be empty or 3-24 lowercase characters, start with a letter, end with a letter or digit, contain only letters, digits, and hyphens, and not contain consecutive hyphens."
  }
}
