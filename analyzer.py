from checks import *

def count_ip_logs(list_data):
    count_ip_logs= {}
    for ip in list_data:
        count_ip_logs[ip[1]]=count_ip_logs.get(ip[1],0)+1
    return count_ip_logs




