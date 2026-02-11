import config
from reader import get_all_suspicious
LINES_READED=int()
LINES_SUSPICION=int()
DICT_SUSPICIOUS={'EXTERNAL_IP':0,"SENSITIVE_PORT":0,'LARGE_PACKET':0,"NIGHT_ACTIVITY":0}

suspicion_checks = {
    "EXTERNAL_IP": lambda row: not row[1].startswith(config.INTERNAL_ADDRS),
    "SENSITIVE_PORT": lambda row: row[3] in config.SENSITIVE_PORTS,
    "LARGE_PACKET":lambda row: int(row[-1].strip())>config.BIGGEST_MSG,
    "NIGHT_ACTIVITY": lambda row: config.NIGHT_START<=row[0].split()[1][:2:]<config.NIGHT_FINISH
}

def suspicion_for_line(dict_sus,line):
    return list(filter(lambda n: dict_sus[n](line),dict_sus.keys()))


def suspicion_line(gen_line):
    for line in gen_line:
        if len(suspicion_for_line(suspicion_checks,line))>0:
            yield line

def touple_suspicion_line(gen_line):
    for line in gen_line:
        yield (line,suspicion_for_line(suspicion_checks,line))

def sum_of_suspicious_lines(gen_line):
    return sum(1 for line in gen_line)

def upgrade_global_sus(gen_line):
    for line in touple_suspicion_line(gen_line):
        config.LINES_READED+=1
        if len(line[1])>0:
             config.LINES_SUSPICION+=1
             for d in line[1]:
                 config.DICT_SUSPICIOUS[d]+= 1
        yield line


