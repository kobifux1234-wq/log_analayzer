from checks import *

def count_ip_logs(list_data):
    count_ip_logs= {}
    for ip in list_data:
        count_ip_logs[ip[1]]=count_ip_logs.get(ip[1],0)+1
    return count_ip_logs

def dict_check_lines(list_data):
    external_ip=set(get_external_addrs(list_data))
    sensitive_port={row[1] for row in flirt_by_sense_port(list_data)}
    large_packet={row[1] for row in size_over_5000(list_data)}
    night_activity={row[1] for row in check_night_activities(list_data)}

    ip_logs=count_ip_logs(list_data)
    dict_suspicious={}

    for key in ip_logs.keys():
        suspicious = []
        if any(key == value for value in external_ip):suspicious.append("EXTERNAL_IP")
        if any(key ==value for value in sensitive_port) :suspicious.append("SENSITIVE_PORT")
        if any(key ==value for value in large_packet):suspicious.append("LARGE_PACKET")
        if any(key ==value for value in night_activity):suspicious.append("NIGHT_ACTIVITY")
        if suspicious: dict_suspicious[key]=suspicious
    return dict_suspicious




