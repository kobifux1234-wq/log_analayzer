from config import *

def get_external_addrs(list_data):
    return [ip[1] for ip in list_data if not ip[1].startswith(INTERNAL_ADDRS)]

def flirt_by_sense_port(list_data):
    return [row for row in list_data if  row[1] in SENSITIVE_PORTS]

def size_over_5000(list_data):
    return [row for row in list_data if int(row[-1].strip())>BIGGEST_MSG]

def check_night_activities(list_data):
    return [row for row in list_data if NIGHT_START<row[0].split()[1]<NIGHT_FINISH]

def traffic_labeling(list_data):
    return['LARGE' if int(row[-1].strip())>BIGGEST_MSG else 'NORMAL' for row in list_data]
