import sys




def help():
    print("The command must include two arguments. A network interface name and an indicator for active or passive mode.\n")
    print("Example 1: net_recon.py -i enp0s3 -p")
    print("Example 2: net_recon.py --iface enp0s3 --passive")
    print("-------------------------------------------------------------------------")
    print("Description of the Tool:\n")
    print("The net_recon.py tool allows a user to passively or actively detect hosts on their network!")







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


# Calling the main function
main()