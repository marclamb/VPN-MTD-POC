import configparser
from pathlib import Path
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule, NetworkSecurityGroup
import paramiko
import time


def load_config():
    config_path = Path(__file__).parent / 'azure_config.ini'
    config = configparser.ConfigParser()
    config.read(config_path)
    
    if 'Azure' not in config:
        config['Azure'] = {}
    
    required_keys = ['tenant_id', 'client_id', 'client_secret', 'subscription_id', 
                     'resource_group_name', 'vnet_name', 'subnet_name', 
                     'ssh_public_key_path', 'ssh_private_key_path', 'peer_public_key', 'allowed_ips']
    for key in required_keys:
        if key not in config['Azure'] or not config['Azure'][key]:
            config['Azure'][key] = input(f"Enter your Azure {key.replace('_', ' ')}: ")
    
    return config['Azure']

def get_ssh_key(config, key_type):
    with open(config[key_type], 'r') as key_file:
        return key_file.read()
    
def create_or_update_nsg(network_client, resource_group_name, location, nsg_name):
    # Define the security rules for SSH and WireGuard
    ssh_rule = SecurityRule(
        access='Allow',
        description='Allow SSH',
        destination_address_prefix='*',
        destination_port_range='22',
        direction='Inbound',
        priority=100,
        protocol='Tcp',
        source_address_prefix='*',
        source_port_range='*',
        provision_state=None,
        name='SSHRule'
    )
    
    wireguard_rule = SecurityRule(
        access='Allow',
        description='Allow WireGuard',
        destination_address_prefix='*',
        destination_port_range='51820',
        direction='Inbound',
        priority=110,
        protocol='Udp',
        source_address_prefix='*',
        source_port_range='*',
        provision_state=None,
        name='WireGuardRule'
    )
    
    # Create or update the NSG with these rules
    nsg_params = NetworkSecurityGroup(
        location=location,
        security_rules=[ssh_rule, wireguard_rule]
    )
    return network_client.network_security_groups.begin_create_or_update(resource_group_name, nsg_name, nsg_params)


def check_or_create_networking(network_client, config, location):
    resource_group_name = config['resource_group_name']
    vnet_name = config['vnet_name']
    subnet_name = config['subnet_name']
    nsg_name = "wireguard-NSG"  # Naming the NSG

    # Ensure VNet is created or retrieved
    try:
        vnet = network_client.virtual_networks.get(resource_group_name, vnet_name)
        print(f"Found VNet: {vnet_name}")
    except:
        print(f"Creating VNet: {vnet_name}")
        vnet_params = {'location': location, 'address_space': {'address_prefixes': ['10.0.0.0/16']}}
        vnet = network_client.virtual_networks.begin_create_or_update(resource_group_name, vnet_name, vnet_params).result()

    # Ensure Subnet is created or retrieved, and NSG is associated
    try:
        subnet = network_client.subnets.get(resource_group_name, vnet_name, subnet_name)
        print(f"Found Subnet: {subnet_name}")
    except:
        print(f"Creating Subnet: {subnet_name}")
        # Create or update NSG to allow SSH and WireGuard
        nsg = create_or_update_nsg(network_client, resource_group_name, location, nsg_name)
        nsg_result = nsg.result()
        print(f"NSG created or updated: {nsg_name}")

        # Subnet parameters include the NSG association
        subnet_params = {
            'address_prefix': '10.0.0.0/24',
            'network_security_group': nsg_result
        }
        subnet = network_client.subnets.begin_create_or_update(resource_group_name, vnet_name, subnet_name, subnet_params).result()

    return vnet, subnet

def provision_vm(compute_client, network_client, config, location, vnet, subnet):
    resource_group_name = config['resource_group_name']
    vm_name = "WireGuardVM"
    ssh_public_key = get_ssh_key(config, 'ssh_public_key_path')

    # Create public IP address
    public_ip_params = {
        'location': location,
        'public_ip_allocation_method': 'Dynamic'
    }
    public_ip = network_client.public_ip_addresses.begin_create_or_update(resource_group_name, vm_name + "PublicIP", public_ip_params).result()

    # Create NIC with public IP
    nic_params = {
        'location': location,
        'ip_configurations': [{
            'name': 'ipconfig1',
            'subnet': {'id': subnet.id},
            'public_ip_address': {'id': public_ip.id}
        }]
    }
    nic = network_client.network_interfaces.begin_create_or_update(resource_group_name, vm_name + "NIC", nic_params).result()

    # VM parameters include the NIC ID
    vm_params = {
        'location': location,
        'os_profile': {
            'computer_name': vm_name, 
            'admin_username': 'azureuser',
            'linux_configuration': {
                'disable_password_authentication': True,
                'ssh': {
                    'public_keys': [{
                        'path': f'/home/azureuser/.ssh/authorized_keys',
                        'key_data': ssh_public_key
                    }]
                }
            }
        },
        'hardware_profile': {'vm_size': 'Standard_B1s'},
        'network_profile': {'network_interfaces': [{'id': nic.id}]},
        'storage_profile': {
            'image_reference': {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-jammy', 'sku': '22_04-lts-gen2', 'version': 'latest'}
        }
    }
    vm = compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm_params).result()
    return vm, nic.name

def get_public_ip_address(network_client, resource_group_name, nic_name):
    try:
        nic = network_client.network_interfaces.get(resource_group_name, nic_name)
        ip_configuration = nic.ip_configurations[0]
        public_ip_address_id = ip_configuration.public_ip_address.id if ip_configuration.public_ip_address else None
        
        if public_ip_address_id:
            public_ip_address_name = public_ip_address_id.split('/')[-1]
            public_ip = network_client.public_ip_addresses.get(resource_group_name, public_ip_address_name)
            return public_ip.ip_address
        else:
            print("No public IP address associated with the NIC.")
            return None
    except Exception as e:
        print(f"Failed to retrieve public IP address: {e}")
        return None

def retry_operation(operation, retries=5, delay=10, timeout=180, retry_condition=None):
    """Generic retry logic."""
    start_time = time.time()
    attempts = 0
    while attempts < retries and (time.time() - start_time) < timeout:
        try:
            return operation()
        except Exception as e:
            if retry_condition and not retry_condition(e):
                raise  # If the retry_condition is provided and returns False, raise the exception
            print(f"Attempt {attempts + 1} failed: {e}")
            time.sleep(delay)
            attempts += 1
    raise Exception("Operation failed after retries and timeout.")

def connect_ssh(ip_address, config, retry_interval=10, max_retries=18):  # 3 minutes total
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    private_key = paramiko.RSAKey.from_private_key_file(config['ssh_private_key_path'])
    retries = 0

    while retries < max_retries:
        try:
            ssh.connect(ip_address, username='azureuser', pkey=private_key, timeout=10)
            print("SSH connection established.")
            return ssh
        except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.SSHException, ConnectionResetError) as e:
            print(f"SSH connection attempt {retries + 1} failed: {e}, retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)
            retries += 1

    raise Exception(f"Failed to connect to VM via SSH after {max_retries * retry_interval} seconds.")

def install_wireguard(ssh):
    """Install WireGuard with retries."""
    command = "sudo apt-get update && sudo apt-get install wireguard -y"
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode() + stderr.read().decode()
    if "Setting up wireguard" not in output:
        raise Exception("Failed to install WireGuard.")
    print(output)

def generate_keys(ssh):
    """Generate WireGuard keys with retries."""
    stdin, stdout, stderr = ssh.exec_command("wg genkey")
    stdout.channel.recv_exit_status()  # Ensure command completion
    private_key = stdout.read().decode().strip()
    if not private_key:
        raise Exception("Failed to generate a private key")

    stdin, stdout, stderr = ssh.exec_command(f"echo {private_key} | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey")
    stdout.channel.recv_exit_status()
    public_key = stdout.read().decode().strip()
    if not public_key:
        raise Exception("Failed to generate or retrieve the WireGuard public key")
    return private_key, public_key

def configure_firewall_and_nat(ssh):
    firewall_and_nat_commands = [
        "sudo sysctl -w net.ipv4.ip_forward=1",
        "sudo sh -c 'echo \"net.ipv4.ip_forward = 1\" >> /etc/sysctl.conf'",
        #"sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        #"sudo iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
        #"sudo iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT",
        #"sudo apt-get install -y iptables-persistent"
        
        #"sudo ufw route allow in on wg0 out on eth0",
        #"sudo iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE",
        #"sudo ufw route delete allow in on wg0 out on eth0",
        #"sudo iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        #"sudo ufw allow 51820/udp",
        #"sudo ufw allow OpenSSH",
        #"sudo ufw disable",
        #"sudo ufw enable"
    ]
    for command in firewall_and_nat_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # Wait for the command to complete
        print(stdout.read().decode())  # Optionally print command output for verification

def setup_wireguard_ssh(ip_address, config):
    ssh = connect_ssh(ip_address, config)
    try:
        retry_operation(lambda: install_wireguard(ssh), retries=5, delay=10)
        private_key, public_key = retry_operation(lambda: generate_keys(ssh), retries=5, delay=10)
        peer_public_key = config['peer_public_key']
        allowed_ips = config['allowed_ips']
        
        wg_conf = (
            f"[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = 10.8.0.1/24\n"
            f"ListenPort = 51820\n"
            f"SaveConfig = true\n\n"
            f"PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE\n"
            f"PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n"
        )
        
        ssh.exec_command(f"echo '{wg_conf}' | sudo tee /etc/wireguard/wg0.conf")
        ssh.exec_command("sudo systemctl enable wg-quick@wg0 && sudo systemctl start wg-quick@wg0")
        
        # Now configure firewall and NAT rules
        configure_firewall_and_nat(ssh)  # Function call to set up IP forwarding and NAT rules
        
    finally:
    #    ssh.close()
        f"\nSSH should be up"

    print("\nWireGuard VPN Server Setup Complete:")
    print(f"Server's Public IP Address: {ip_address}")
    print(f"Server's Public Key: {public_key}")
    print("WireGuard Listening Port: 51820")
    print(f"VPN IP Address: 10.8.0.1/24")
    print(f"Peer Public Key: {peer_public_key}")
    #print(f"Allowed IPs: {allowed_ips}")
    
    print("\n")
    print(f"Example WireGuard Clinet Configuration File (any DNS should work):")
    print(f"\n[Interface]")
    print("PrivateKey = [client generated key should already be populated]")
    print(f"Address = 10.8.0.2/24")
    print(f"DNS = 8.8.8.8, 8.8.4.4")
    print(f"\n[Peer]")
    print(f"Public Key = {public_key}")
    print("AllowedIPs = 10.8.0.0/24")
    print(f"Endpoint = {ip_address}:51820")
    print(f"PersistentKeepalive = 25")
    print(f"\n")

def main():
    # Existing setup code here...
    # Example of calling setup_wireguard_ssh
    config = load_config()
    credential = ClientSecretCredential(tenant_id=config['tenant_id'], client_id=config['client_id'], client_secret=config['client_secret'])
    subscription_id = config['subscription_id']

    network_client = NetworkManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    location = 'eastus'

    vnet, subnet = check_or_create_networking(network_client, config, location)
    vm, nic_name = provision_vm(compute_client, network_client, config, location, vnet, subnet)
    ip_address = get_public_ip_address(network_client, config['resource_group_name'], nic_name)
    setup_wireguard_ssh(ip_address, config)

if __name__ == "__main__":
    main()