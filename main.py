from checks import *
import config
from pathlib import Path


def analyze_log(file_path):
    risky_ip = {}
    generator_line = get_all_suspicious(file_path)

    risk_ip_touple=upgrade_global_sus(generator_line)
    for i in risk_ip_touple:
        if i[0][1] in risky_ip:
            risky_ip[i[0][1]] = list(set(i[1]+risky_ip[i[0][1]]))
        else:
            risky_ip[i[0][1]]=i[1]
    return risky_ip


def generate_report(suspicious_dict):
    high_risk=''
    risky_ip = ''
    for i in suspicious_dict:
        if len(i[1])>=3:
            high_risk+=f'- {i}: {suspicious_dict[i]}\n'
        elif len(i[1])>0:
            risky_ip+=f'- {i}: {suspicious_dict[i]}\n'
    report = \
f"""=======================================
דוח תעבורה חשודה
=======================================
:סטטיסטיקות כלליות
שורות שנקראו: -{config.LINES_READED}
שורות חשודות: -{config.LINES_SUSPICION}
- EXTERNAL_IP: {config.DICT_SUSPICIOUS["EXTERNAL_IP"]}
- SENSITIVE_PORT: {config.DICT_SUSPICIOUS["SENSITIVE_PORT"]}
- LARGE_PACKET: {config.DICT_SUSPICIOUS["LARGE_PACKET"]}
- NIGHT_ACTIVITY: {config.DICT_SUSPICIOUS["NIGHT_ACTIVITY"]}
:עם רמת סיכון גבוהה ( +3חשדות) IPs
{high_risk}
:חשודים נוספים IPs
{risky_ip}"""
    return report


def save_report(report,file_path):
    path_to_security_file=Path(config.FILE_PATH).parent/file_path
    path_to_security_file.write_text(report,encoding='utf-8')


def main():
    suspicious=analyze_log(config.FILE_PATH)
    report=generate_report(suspicious)
    print(report)
    save_report(report,'security_report.txt')

if __name__ == "__main__":
    main()