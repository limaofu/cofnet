import cofnet

if __name__ == '__main__':
    ip_range = "10.99.1.8-12"
    print(cofnet.generate_ip_list_by_ip_range(ip_range))
    ip_range_2 = "10.99.1.8-10.99.1.12"
    print(cofnet.generate_ip_list_by_ip_range_2(ip_range_2))
