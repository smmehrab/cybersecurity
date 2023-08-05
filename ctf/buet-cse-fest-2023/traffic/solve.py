# tshark -r traffic.pcap -T fields -e eth.src -e eth.dst > mac_addresses.txt
import hashlib

mac_addresses_file = "mac_addresses.txt"  # Replace with the path to your file

# Read the MAC addresses from the file
with open(mac_addresses_file, 'r') as file:
    mac_addresses = file.readlines()

# Clean up the MAC addresses (remove leading/trailing spaces and newlines)
mac_addresses = [address.strip() for address in mac_addresses]

# Find distinct MAC addresses
mac_addresses = set(mac_addresses)


distinct_mac_addresses = []

# Process each element in the array
for element in mac_addresses:
    # Split the element by spaces
    addresses = element.split()
    
    # Add each MAC address to the flattened array
    distinct_mac_addresses.extend(addresses)

# correct
correct_hash = "c4c82d78cd9426a35b913fa5fe2d1cd2a1a6922528d70f66c11fb7aefd45cad62db09a2fc9391bf7ebaca26a3481ba4a357c91c115d41d44b55c28fe7621ce07"
print(correct_hash)

# Print the distinct MAC addresses
for mac_address in distinct_mac_addresses:
    print(mac_address)

# BCF2023{00:21:5d:9e:42:fb}
