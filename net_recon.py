import sys
from scapy.all import sniff, ARP



def help():
    print("The command must include two arguments. A network interface name and an indicator for active or passive mode.\n")
    print("Example 1: net_recon.py -i enp0s3 -p")
    print("Example 2: net_recon.py --iface enp0s3 --passive")
    print("-------------------------------------------------------------------------")
    print("Description of the Tool:\n")
    print("The net_recon.py tool allows a user to passively or actively detect hosts on their network!")

# Function to display detected MAC-IP pairs in a table format
def display_table(detected_pairs, interface, mode):
    # Clear the console
    print("\033c", end="")

    # Header information
    print(f"Interface: {interface}      Mode: {mode}      Found {len(detected_pairs)} hosts")
    print("-" * 100)

    if (mode=="Active"):
        print(f"{'MAC':<20}{'IP':<20}")
        print("-" * 100)

        # Print each MAC-IP pair
        for mac, ip in detected_pairs.items():
            print(f"{mac:<20}{ip:<20}")
        
        print("-" * 100)
    elif (mode=="Passive"):
        print(f"{'MAC':<20}{'IP':<20}{'Host Activity':<15}")
        print("-" * 100)

        # Sort detected_pairs by activity (number of packets) in descending order
        sorted_pairs = sorted(detected_pairs.items(), key=lambda item: item[1][1], reverse=True)

        # Print each MAC-IP pair along with the packet count
        for mac, (ip, activity) in sorted_pairs:
            print(f"{mac:<20}{ip:<20}{activity:<15}")
        
        print("-" * 100)



def passive_scan(interface):
    print(f"Starting passive scan on interface {interface}. Press Ctrl+C to stop.")
    
    # Dictionary to store unique IP-MAC pairs
    detected_pairs = {}

    def arp_callback(packet):
        # Check for ARP reply (opcode 2) packets
        if ARP in packet and packet[ARP].op == 2:  # 2 is "is-at" or ARP reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            # Add new pairs to dictionary and display them
            # If this MAC address is already detected, update the packet count
            if src_mac in detected_pairs:
                detected_pairs[src_mac] = (src_ip, detected_pairs[src_mac][1] + 1)
            else:
                # New host detected: Add to the dictionary with a packet count of 1
                detected_pairs[src_mac] = (src_ip, 1)

            # Update display
            display_table(detected_pairs, interface, "Passive")

    try:
        # Sniff ARP packets on the specified interface with a callback function
        sniff(iface=interface, filter="arp", prn=arp_callback, store=False)
    except KeyboardInterrupt:
        print("\nPassive scan terminated by user.")
    except Exception as e:
        print(f"Error: {e}")





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
        if(arg == "-p" or arg =="--passive"):
            passive = True
            active = False
            modeflag = True
        elif(arg == "-a" or arg == "==active"):
            active = True
            passive = False
            modeflag = True
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
    elif(active):
        pass


# Calling the main function
main()