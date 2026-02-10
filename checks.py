from config import *
from reader import *

#list_data=lists_for_file(FILE_PATH)
#list_bytes=[int(n[-1]) for n in list_data]

#get_size_in_kb= list(map(lambda x: x/1024,list_bytes))

# get_night_hours=list(map(lambda x: x[0].split()[1][:2:],list_data))
# get_line_sensetive_port=list(filter(lambda x:x[3] in SENSITIVE_PORTS,list_data))
# get_sleep_hours =list(filter(lambda x: NIGHT_START<=x[0].split()[1][:2:]<NIGHT_FINISH,list_data))

# suspicion_checks = {"EXTERNAL_IP": lambda row: not row[1].startswith(INTERNAL_ADDRS),
#                         "SENSITIVE_PORT": lambda row: row in get_line_sensetive_port, "LARGE_PACKET":
#                             lambda row: int(row[-1].strip())>BIGGEST_MSG, "NIGHT_ACTIVITY": lambda row:
#         row in get_sleep_hours}

# def traffic_labeling(list_data):
#     return['LARGE' if int(row[-1].strip())>BIGGEST_MSG else 'NORMAL' for row in list_data]
#
# def port_to_protocol(list_data):
#     return {row[3]:row[4] for row in list_data}


suspicion_checks = {
    "EXTERNAL_IP": lambda row: not row[1].startswith(INTERNAL_ADDRS),
    "SENSITIVE_PORT": lambda row: row[3] in SENSITIVE_PORTS,
    "LARGE_PACKET":lambda row: int(row[-1].strip())>BIGGEST_MSG,
    "NIGHT_ACTIVITY": lambda row: NIGHT_START<=row[0].split()[1][:2:]<NIGHT_FINISH
}

def suspicion_for_line(dict_sus,line):
    return list(filter(lambda n: dict_sus[n](line),dict_sus.keys()))
#line_in_suspicion=list(map(lambda line:suspicion_for_line(suspicion_checks,line),list_data))
#line_suspicion_over_2=list(filter(lambda n:len(n)>1,line_in_suspicion))

def suspicion_line(gen_line):
    for line in gen_line:
        if len(suspicion_for_line(suspicion_checks,line))>0:
            yield line
def touple_suspicion_line(gen_line):
    for line in gen_line:
        yield (line,suspicion_for_line(suspicion_checks,line))
def sum_of_suspicious_lines(gen_line):
    return sum(1 for line in gen_line)


