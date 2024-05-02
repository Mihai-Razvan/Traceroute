import socket
import requests
import ipaddress
import ipinfo

icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
icmp_recv_socket.bind(('192.168.85.200', 0))
icmp_recv_socket.settimeout(2)

def traceroute(ip):
    print("\nTracerouting for address: " + ip + "\n")
    TTL = 1
    tries = 3
    while True:
        udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)
        udp_send_sock.sendto(b'', (ip, 33434))
        udp_send_sock.close()

        try:
            data, addr = icmp_recv_socket.recvfrom(65535)
            ip_address = addr[0]
            print(str(TTL) + ". " + ip_address + " ----- " + getIpInfo(ip_address))
            TTL += 1
            tries = 3

            if ip_address == ip:
                print("Address reached")
                return
        except socket.timeout as e:
            tries -= 1
            if tries == 0:
                print(str(TTL) + ". ??????")
                TTL += 1
                tries = 3


def getIpInfo(ip):
    if ipaddress.ip_address(ip).is_private:
        return "Private address"

    access_token = '93985b0c902b8c'            #from ipinfo documentation
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip)
    return "Country: " + details.country + " ----- Region: " + details.region + " ----- City: " + details.city



##############   MAIN   ##########################

traceroute('8.8.8.8') # google dns

# .au sites
#traceroute('104.200.22.130') # yahoo.com.au
#traceroute('172.67.8.209') # ozbargain.com.au

# .in sites
#traceroute('142.250.189.227') # google.co.in
#traceroute('106.10.248.150') # yahoo.in

# .za sites
#traceroute('216.239.38.21') # timeslive.co.za
#traceroute('104.22.46.73') # mybroadband.co.za

#traceroute('104.22.40.244')
