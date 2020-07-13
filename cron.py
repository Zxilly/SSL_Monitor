import json
import socket
import ssl
from datetime import datetime

from domain_list import *

time_recognition_format_string = "%b %d %H:%M:%S %Y GMT"
time_generation_format_string = "%Y-%m-%d %H:%M:%S UTC"


def get_cert(hostname, port=443):
    c = ssl.create_default_context()
    s = c.wrap_socket(socket.socket(), server_hostname=hostname)
    s.connect((hostname, port))
    cert = s.getpeercert()
    return cert


"""
def write_scv(info_list):
    with open('cert.csv',mode='w+',newline='') as csvfile:
        for one_domain_info
"""


def write_json(info_list):
    with open('cert.json', mode='w+', newline='') as json_file:
        json_file.write(json.dumps(info_list))


def analyze_cert(cert, domain):
    common_name = cert['subject'][0][0][1]
    issuer = cert['issuer'][-1][0][1]
    # print(cert['issuer'])
    # print(issuer)
    serial_name = cert["serialNumber"]
    not_before = cert['notBefore']
    not_after = cert['notAfter']
    alt_name = ''
    for one in cert['subjectAltName']:
        alt_name += one[1]
        alt_name += ';&nbsp;'

    not_before_struct_time = datetime.strptime(not_before, time_recognition_format_string)  # Jun  2 05:09:43 2020 GMT
    not_after_struct_time = datetime.strptime(not_after, time_recognition_format_string)
    time_now = datetime.utcnow()

    not_before = datetime.strftime(not_before_struct_time, time_generation_format_string)
    not_after = datetime.strftime(not_after_struct_time, time_generation_format_string)
    expire_time_struct_time = not_after_struct_time - time_now
    expire_time = expire_time_struct_time.days
    pass_percent = (time_now - not_before_struct_time) / (not_after_struct_time - not_before_struct_time) * 100

    info = {"domain": domain, "commonName": common_name, "issuer": issuer, "serialName": serial_name,
            "notBefore": not_before, "notAfter": not_after, "expireTime": expire_time, "passPercent": pass_percent,
            "altName": alt_name}
    # info = [domain, common_name, issuer, serial_name, not_before, not_after, alt_name]
    return info


if __name__ == '__main__':
    info_list = []
    for one in domain_list:
        cert_content = get_cert(one)
        info = analyze_cert(cert_content, one)
        info_list.append(info)
        print(info["domain"] + " finished")
    write_json(info_list)
    # print(info_list)

""""
print(ai)
print(ai['subject'][0][0][1]) # 证书公用名
print(ai['issuer'][2][0][1]) # 证书签发方
print(ai["serialNumber"]) # 证书序列号
#print(ai['notBefore']) # 生效时间
#print(ai['notAfter']) # 失效时间
for one in ai['subjectAltName']:
    print(one[1]) # 备用域名
"""
