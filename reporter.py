
def port_to_protocol(list_data):
    return {row[3]:row[4] for row in list_data}

def min_2_suspicious(dict_sus):
    return {ip:reason for ip,reason in dict_sus.items() if len(reason)>=2}