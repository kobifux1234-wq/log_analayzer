from pathlib import Path

def lists_for_file(path):
    file_log=Path(path)
    with open(file_log,'r')as f:
        return [row.split(',') for row in f]

def zip_addr_ip(list_data):
    return [ip[1] for ip in list_data if not ip[1].startswith(('192.168','10.'))]

def filt_by_sense_port(list_data):
    return [row for row in list_data if  row[3] in ['22','23','3389']]

def size_over_5000(list_data):
    return [row for row in list_data if int(row[-1].strip())>5000]
def traffic_labeling(list_data):
    return['LARGE' if int(row[-1].strip())>5000 else 'NORMAL' for row in list_data]

print (traffic_labeling(lists_for_file('C:\\PythonCode\\log_analayzer\\log_analyzer\\network_traffic.log')))