import subprocess
import time

MAX_CONNECTIONS = 30
OPENVPN_STATUS_LOG = "/etc/openvpn/server/openvpn-status.log"
OPENVPN_PORT = 1194
CHECK_INTERVAL = 1
BLOCK_DURATION = 60
CLIENTS_FILE = "clients.txt"

def create_ipset():
    subprocess.run(["sudo", "ipset", "create", "allowed_clients", "hash:ip"])

def read_clients_file():
    clients = set()
    with open(CLIENTS_FILE, "r") as f:
        for line in f:
            clients.add(line.strip())
    return clients

def update_ipset(clients_ips):
    subprocess.run(["sudo", "ipset", "flush", "allowed_clients"])
    for ip in clients_ips:
        subprocess.run(["sudo", "ipset", "add", "allowed_clients", ip])

def read_openvpn_status_log():
    with open(OPENVPN_STATUS_LOG, "r") as f:
        lines = f.readlines()
        new_clients = set()
        for line in lines:
            if line.startswith("CLIENT_LIST"):
                client = line.split(",")[1].strip()
                ip = line.split(",")[2].strip().split(":")[0]
                if client != "UNDEF":
                    new_clients.add(ip)
    return new_clients

def save_ips_to_clients_file(ips):
    with open(CLIENTS_FILE, "a") as f:
        for ip in ips:
            f.write(f"{ip}\n")

def block_port():
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(OPENVPN_PORT), "-m", "set", "!", "--match-set", "allowed_clients", "src", "-j", "DROP"])

def unblock_port():
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(OPENVPN_PORT), "-m", "set", "!", "--match-set", "allowed_clients", "src", "-j", "DROP"])

def get_connections_on_port(port):
    connections = 0
    output = subprocess.check_output(f"netstat -an | grep ':{port}'", shell=True).decode("utf-8")
    for line in output.splitlines():
        if "ESTABLISHED" in line:
            connections += 1
    return connections

def monitor_connections():
    port_blocked = False
    block_start_time = 0

    while True:
        time.sleep(CHECK_INTERVAL)
        
        new_clients_ips = read_openvpn_status_log()
        clients_ips = read_clients_file()
        new_ips_to_save = new_clients_ips - clients_ips
        save_ips_to_clients_file(new_ips_to_save)
        clients_ips.update(new_clients_ips)
        update_ipset(clients_ips)

        current_connections = get_connections_on_port(OPENVPN_PORT)
        connections_per_second = current_connections / CHECK_INTERVAL

        if connections_per_second > MAX_CONNECTIONS and not port_blocked:
            print("Attack detected!")
            block_port()
            port_blocked = True
            block_start_time = time.time()

        if port_blocked and time.time() - block_start_time >= BLOCK_DURATION:
            print("Unblocking the port...")
            unblock_port()
            port_blocked = False

if __name__ == "__main__":
    create_ipset()
    monitor_connections()