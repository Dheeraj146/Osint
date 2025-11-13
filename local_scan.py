import nmap

# Find your private IP address by opening Command Prompt and typing 'ipconfig'
# It will likely start with 192.168.x.x
your_private_ip = "10.226.14.149" # <-- CHANGE THIS to your actual private IP

nm = nmap.PortScanner()
print(f"Scanning {your_private_ip}...")
nm.scan(your_private_ip, '21,22,80,443')

if your_private_ip in nm.all_hosts():
    for port in nm[your_private_ip]['tcp'].keys():
        if nm[your_private_ip]['tcp'][port]['state'] == 'open':
            print(f"Port {port} is open")
else:
    print("Host seems down.")