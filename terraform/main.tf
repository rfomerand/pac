# File: terraform/infrastructure/web-server.tf
# This VM resource will trigger a conflict between Sentinel and Azure policies

resource "azurerm_resource_group" "web_rg" {
  name     = "rg-webserver-prod-001"
  location = "East US"
  
  tags = {
    environment = "production"
    application = "web-frontend"
    owner       = "devops-team@company.com"
  }
}

resource "azurerm_virtual_network" "web_vnet" {
  name                = "vnet-web-prod-001"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.web_rg.location
  resource_group_name = azurerm_resource_group.web_rg.name
}

resource "azurerm_subnet" "web_subnet" {
  name                 = "snet-web-prod-001"
  resource_group_name  = azurerm_resource_group.web_rg.name
  virtual_network_name = azurerm_virtual_network.web_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_interface" "web_nic" {
  name                = "nic-webserver-prod-001"
  location            = azurerm_resource_group.web_rg.location
  resource_group_name = azurerm_resource_group.web_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.web_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# THIS RESOURCE WILL TRIGGER THE POLICY CONFLICT
# The VM size "Standard_D2s_v3" is:
# - ALLOWED by Terraform Sentinel policy (in approved_vm_sizes list)
# - DENIED by Azure Policy (in listOfDeniedSKUs)
resource "azurerm_linux_virtual_machine" "web_server" {
  name                = "vm-webserver-prod-001"
  location            = azurerm_resource_group.web_rg.location
  resource_group_name = azurerm_resource_group.web_rg.name
  
  # This size causes the conflict!
  size                = "Standard_D2s_v3"  # Allowed by Sentinel, Denied by Azure Policy
  
  admin_username      = "adminuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  network_interface_ids = [
    azurerm_network_interface.web_nic.id,
  ]

  tags = {
    environment  = "production"
    application  = "web-frontend"
    approved_by  = "platform-team"  # Approved by platform team (Sentinel)
    vm_size_note = "This size passes Sentinel but will be blocked by Azure Policy"
  }
}
