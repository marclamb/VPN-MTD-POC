# VPN-MTD-POC
Cheap VPN and MTD POC

**Getting Started with Azure Resource Setup Using Python**
This guide provides a detailed walkthrough on how to use the provided Python script and configuration file to set up Azure resources, specifically targeting the creation and configuration of a virtual network and a virtual machine to run WireGuard, a modern VPN protocol. The guide assumes familiarity with Azure, Python, and basic networking concepts.

**Prerequisites**
Before you begin, make sure you have the following prerequisites:

1. An Azure account with appropriate permissions to create and manage resources.
2. Python installed on your system.
3. The Azure SDK for Python installed. You can install it using pip:

**pip install azure-identity azure-mgmt-compute azure-mgmt-network paramiko**

**Configuration File Setup**
First, update the **azure_config.ini** file with your Azure credentials and target resource specifications. Here is the template structure of **azure_config.ini**:

**[Azure]**
**tenant_id** = your_tenant_id
**client_id** = your_client_id
**client_secret** = your_client_secret
**subscription_id** = your_subscription_id
**resource_group_name** = desired_resource_group_name
**vnet_name** = desired_vnet_name
**subnet_name** = desired_subnet_name
**ssh_public_key_path** = path_to_your_public_ssh_key
**ssh_private_key_path** = path_to_your_private_ssh_key
**peer_public_key** = your_wireguard_peer_public_key
**allowed_ips** = wireguard_allowed_ips
Replace each placeholder with your actual data. This configuration will be read by the Python script to set up the Azure environment.

**Python Script Overview**
The Python script **AzureWGproject.py** performs the following tasks:

1. Configuration Loading: Reads the Azure configuration from azure_config.ini.
2. Azure Authentication: Uses credentials from the configuration to authenticate against Azure services.
3. Network Setup: Creates a virtual network and subnet if they do not exist.
4. Virtual Machine Provisioning: Sets up a virtual machine and configures its network interfaces.
5. WireGuard and SSH Configuration: Configures the virtual machine to run WireGuard and allows SSH access.

Here is a brief rundown of key functions in the script:

**load_config()**: Loads Azure configuration settings from the INI file.
**get_ssh_key(config, key_type)**: Retrieves SSH keys from the specified file paths.
**create_or_update_nsg(network_client, resource_group_name, location, nsg_name)**: Configures network security groups to allow SSH and WireGuard traffic.
**setup_wireguard_ssh(ip_address, config)**: Sets up WireGuard on the virtual machine using SSH commands.

**Running the Script**
To execute the script, simply run the following command in the terminal where your Python environment is set up:

**python AzureWGproject.py**
The script will interactively request any missing configuration values, set up the necessary Azure resources, and provide output regarding the status of operations.

**Post-Setup Configuration**
After the resources are set up, you may want to configure your WireGuard client. Reference the provided DigitalOcean tutorial for detailed guidance on setting up WireGuard on Ubuntu 22.04, which can be applied similarly to your setup: How to Set Up WireGuard on Ubuntu 22.04. (https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-22-04)

**Conclusion**
This Python script and configuration setup provide a streamlined approach to deploying a WireGuard VPN in the Azure cloud. Adjust the script and configurations according to your specific requirements and security guidelines. ​
