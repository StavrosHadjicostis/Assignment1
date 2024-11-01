import sys
from scapy.all import sniff, ARP, Ether, srp
import os


#Function that prints messages to the user if the command wasn't submitted as it should
def help():
    print("The command must include two arguments. A network interface name and an indicator for active or passive mode.\n")
    print("Example 1: net_recon.py -i enp0s3 -p")
    print("Example 2: net_recon.py --iface enp0s3 --passive")
    print("-" * 100)
    print("Description of the Tool:\n")
    print("The net_recon.py tool allows a user to passively or actively detect hosts on their network!")

# Function to display detected MAC-IP pairs in a table format
def display_table(detected_pairs, interface, mode):
    # Clears the console
    print("\033c", end="")

    # Header information about Interface, Mode and Hosts
    print(f"Interface: {interface}      Mode: {mode}      Found {len(detected_pairs)} hosts")
    print("-" * 100)

    #Checks if the user has choosen the Active mode
    if (mode=="Active"):
        print(f"{'MAC':<20}{'IP':<20}")
        print("-" * 100)

        # Prints each MAC-IP pair detected
        for mac, ip in detected_pairs.items():
            print(f"{mac:<20}{ip:<20}")
        
        print("-" * 100)
    #Checks if the user has choosen the Passive mode
    elif (mode=="Passive"):
        print(f"{'MAC':<20}{'IP':<20}{'Host Activity':<15}")
        print("-" * 100)

        # Sorts detected_pairs by activity (number of packets) in descending order
        sorted_pairs = sorted(detected_pairs.items(), key=lambda item: item[1][1], reverse=True)

        # Prints each MAC-IP pair along with the packet count
        for mac, (ip, activity) in sorted_pairs:
            print(f"{mac:<20}{ip:<20}{activity:<15}")
        
        print("-" * 100)


#Function that performs the passive scan
def passive_scan(interface):
    print(f"Starting passive scan on interface {interface}. Press Ctrl+C to stop.")
    
    # Dictionary to store unique IP-MAC pairs
    detected_pairs = {}

    #Callback function that is called into the sniff
    def arp_callback(packet):
        # Checks for ARP reply packets (opcode 2)
        if ARP in packet and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            # Add new pairs to dictionary and display them
            # If this MAC address is already detected, update the packet count
            if src_mac in detected_pairs:
                detected_pairs[src_mac] = (src_ip, detected_pairs[src_mac][1] + 1)
            # New host detected
            else:   
                #Adds to the dictionary with a packet count of 1             
                detected_pairs[src_mac] = (src_ip, 1)

            # Updates display
            display_table(detected_pairs, interface, "Passive")

    try:
        # Sniff ARP packets on the specified interface with the callback function
        sniff(iface=interface, filter="arp", prn=arp_callback, store=False)
    #Handles the Termination
    except KeyboardInterrupt:
        print("\nPassive scan terminated by user.")
    #Handles the Errors
    except Exception as e:
        print(f"Error: {e}")

#Function that performs the active reconnaissance
def active_recon(interface):

    # Gets the interface IP address
    try:
        # Getting the interface IP
        ip_output = os.popen(f"ip addr show {interface}").read()
        # Extracting the IP address
        interface_ip = ip_output.split("inet ")[1].split("/")[0]
    # Handles the exceptions
    except Exception as e:
        print(f"Error: Could not retrieve IP address for interface {interface}. {e}")
        sys.exit(1)
    
    # Generates a list of IP addresses in the same /24 subnet
    network_prefix = '.'.join(interface_ip.split('.')[:-1])  # Get the first three octets
    ip_range = [f"{network_prefix}.{i}" for i in range(1, 255)]  # Generate IPs from 1 to 254

    print(f"Sending ARP requests on network from {interface_ip}/24")

    # Creates an ARP request packet for each IP in the range
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Sends the ARP requests and capturing the replies
    answered, unanswered = srp(arp_request, timeout=2, iface=interface, verbose=0)

    # Stores detected MAC-IP pairs
    detected_hosts = {}
    for sent, received in answered:
        detected_hosts[received.psrc] = received.hwsrc

    # Displays the Table
    display_table(detected_hosts, interface, "Active")



def main():
    print("Welcome to net_recon tool!!\n")
    # total arguments
    n = len(sys.argv)

    # Checking if we have the correct number of arguments. If we don't then we call the help() function and we terminate the scrypt.
    if (n!=4):
        help()
        sys.exit(1)

    # Flags for checking if we collected all the information
    modeflag = False
    iflag = False
    
    # Checking the arguments and collecting the information from them
    for i in range(1, n):
        arg = sys.argv[i]
        # Checks if the passive mode is selected
        if(arg == "-p" or arg =="--passive"):
            passive = True
            active = False
            modeflag = True
        # Checks if the active mode is selected
        elif(arg == "-a" or arg == "==active"):
            active = True
            passive = False
            modeflag = True
        # Checks if the interface is entered
        elif(arg == "-i" or arg == "--iface"):
            if(i+1>n):
                help()
                sys.exit(1)            
            interface = sys.argv[i+1]
            iflag = True

    # Checking if all the nessesary information was collected, if not then it means that the user has done something wrong so we call the help() function and exit
    if(modeflag==False or iflag==False):
        help()
        sys.exit(1)

    # If the user choosen the passive mode then we call the passive_scan function
    if(passive):
        passive_scan(interface)
    # If the user choosen the active mode then we call the active_recon function
    elif(active):
        active_recon(interface)


# Calling the main function
main()
