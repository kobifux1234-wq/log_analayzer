from checks import *

generator_line= get_all_suspicious(FILE_PATH)
suspicious =suspicion_line(generator_line)
detailed= touple_suspicion_line(suspicious)
count= sum_of_suspicious_lines(detailed)
for i in detailed:
    print(i)
print(f'Total suspicious {count}')

