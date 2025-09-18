import cofnet3 as cofnet

if __name__ == '__main__':
    ip_range = "10.99.1.8-12"
    print("ip_range: ", cofnet.generate_ip_list_by_ip_range(ip_range))
    ip_range_2 = "10.99.1.8-10.99.1.12"
    print("ip_range_2: ", cofnet.generate_ip_list_by_ip_range_2(ip_range_2))
    maskbyte = "255.255.254.0"
    print("maskbyte: ", cofnet.is_maskbyte(maskbyte), cofnet.maskbyte_to_maskint(maskbyte))
    print("hex: ", cofnet.ip_to_hex_string("10.99.1.2"))
    print("get_maskint_with_space: ", cofnet.get_maskint_with_space(9))
