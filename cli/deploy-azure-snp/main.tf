# Configure the Azure provider
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.57.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~>3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~>4.0"
    }
  }

  required_version = ">= 1.2.0"
}

provider "azurerm" {
  resource_provider_registrations = "none"
  // subscription_id = "7ce87326-fea1-4c35-8c52-99a44a98e250"
  features {}
}

data "azurerm_resources" "tls_keyvault" {
  count = var.tls_keyvault_name == "" ? 0 : 1

  name = var.tls_keyvault_name
  type = "Microsoft.KeyVault/vaults"
}

#data "azurerm_resource_group" "rg" {
#  name     = var.resource_group_name
#}

resource "random_string" "random_name" {
  length  = 10
  special = false
  lower   = true
  upper   = false
  numeric = false
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.resource_group_location
  tags     = var.deployment_tags
}

# Create virtual network
resource "azurerm_virtual_network" "my_terraform_network" {
  name                = "myVnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Create subnet
resource "azurerm_subnet" "my_terraform_subnet" {
  name                 = "mySubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.my_terraform_network.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create public IPs
resource "azurerm_public_ip" "my_terraform_public_ip" {
  name                = "myPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "my_terraform_nsg" {
  name                = "myNetworkSecurityGroup"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "HTTP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS_App"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Create network interface
resource "azurerm_network_interface" "my_terraform_nic" {
  name                = "myNIC"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "my_nic_configuration"
    subnet_id                     = azurerm_subnet.my_terraform_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.my_terraform_public_ip.id
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.my_terraform_nic.id
  network_security_group_id = azurerm_network_security_group.my_terraform_nsg.id
}

# Create (and display) an SSH key
resource "tls_private_key" "example_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}


# Create storage account
resource "azurerm_storage_account" "temen_os_sa" {
  name                            = "temenacc${random_string.random_name.id}" #var.storage_account
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
}

# Create storage container
resource "azurerm_storage_container" "temen_os_container" {
  name                  = "temencon${random_string.random_name.id}" #var.storage_container
  storage_account_name  = azurerm_storage_account.temen_os_sa.name
  container_access_type = "private"
}

# Upload VHD to container
resource "null_resource" "vhd_upload" {
  triggers = {
    file_path           = var.vhd_path
    file_sha256         = var.vhd_sha256
    storage_account     = azurerm_storage_account.temen_os_sa.name
    upload_wait_version = "1"
  }

  provisioner "local-exec" {
    command = <<EOT
      az storage blob upload \
        --account-name ${azurerm_storage_account.temen_os_sa.name} \
        --container-name ${azurerm_storage_container.temen_os_container.name} \
        --file ${var.vhd_path} \
        --name temen-os.vhd \
        --type page \
        --max-connections 8 \
        --overwrite

      for i in $(seq 1 60); do
        if az storage blob show \
          --account-name ${azurerm_storage_account.temen_os_sa.name} \
          --container-name ${azurerm_storage_container.temen_os_container.name} \
          --name temen-os.vhd \
          --query name \
          --output tsv >/dev/null 2>&1; then
          exit 0
        fi
        sleep 5
      done

      echo "Timed out waiting for uploaded VHD blob to become visible" >&2
      exit 1
    EOT
  }
}
# Create image from VHD
resource "azurerm_shared_image_gallery" "sig_temen_os" {
  name                = var.gallery_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  description         = "Gallery that hosts temen OS image."
  depends_on          = [null_resource.vhd_upload]
}

resource "azurerm_shared_image" "temen_os_image" {
  name                = var.image_name
  gallery_name        = azurerm_shared_image_gallery.sig_temen_os.name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  hyper_v_generation  = "V2"
  #specialized = true
  confidential_vm_supported = true

  identifier {
    publisher = "Midnight"
    offer     = "enclave"
    sku       = "enclaveSku"
  }
  depends_on = [null_resource.vhd_upload]
}

resource "azurerm_shared_image_version" "temen_os_image_version" {
  name                = "0.1.0"
  gallery_name        = azurerm_shared_image.temen_os_image.gallery_name
  image_name          = azurerm_shared_image.temen_os_image.name
  resource_group_name = azurerm_shared_image.temen_os_image.resource_group_name
  location            = azurerm_resource_group.rg.location

  blob_uri           = "https://${azurerm_storage_account.temen_os_sa.name}.blob.core.windows.net/${azurerm_storage_container.temen_os_container.name}/temen-os.vhd"
  storage_account_id = azurerm_storage_account.temen_os_sa.id

  target_region {
    name                   = azurerm_resource_group.rg.location
    regional_replica_count = 1
    storage_account_type   = "Standard_LRS"
  }

  depends_on = [null_resource.vhd_upload]

  lifecycle {
    replace_triggered_by = [null_resource.vhd_upload]
  }
}

resource "azurerm_linux_virtual_machine" "temen_os_vm" {
  name                  = var.vm_name
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.my_terraform_nic.id]
  size                  = var.instance_type

  vtpm_enabled        = true
  secure_boot_enabled = false

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    name                     = "temen-os-disk"
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    security_encryption_type = "VMGuestStateOnly"
  }

  # Image id of uploaded temen OS image
  source_image_id = azurerm_shared_image.temen_os_image.id

  admin_username = "azureuser"

  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.example_ssh.public_key_openssh
  }

  tags = var.tls_keyvault_name == "" ? {} : {
    temenos_tls_keyvault_name = var.tls_keyvault_name
  }

  depends_on = [azurerm_shared_image_version.temen_os_image_version]

}

resource "azurerm_role_assignment" "tls_keyvault_secrets_user" {
  count = var.tls_keyvault_name == "" ? 0 : 1

  scope                = try(data.azurerm_resources.tls_keyvault[0].resources[0].id, "")
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.temen_os_vm.identity[0].principal_id

  lifecycle {
    precondition {
      condition     = length(data.azurerm_resources.tls_keyvault[0].resources) == 1
      error_message = "Azure Key Vault ${var.tls_keyvault_name} was not found or is not visible in this subscription. Create/upload it first with veritee upload-tls-certs, or pass the correct --tls-keyvault-name."
    }
  }
}
