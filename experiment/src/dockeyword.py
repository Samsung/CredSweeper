import re
import sys

BLANK = r'\s'
DASH = r'-'
DOUBLE_DASH = r'--'
COLON = ':'
SLASH = '/'
DOUBLE_SLASH = '//'
EQUAL_SIGN = '='
L_PAREN = r'\('
R_PAREN = r'\)'
L_BRACKET = r'\['
R_BRACKET = r'\]'
GT_SIGN = '>'
LT_SIGN = '<'
COMMA = ','
VERB = r" *(is|는|은|설정은) *"
ANY = r"\S{3,}"
PASSWD_VALUE = fr"(?P<value>{ANY})"
ID_VALUE = fr"(?P<value_id>{ANY})"
SECRET_VALUE = fr"(?P<value>{ANY})"
ALIAS_VALUE = fr"(?P<value_alias>{ANY})"
DIGIT = r"[0-9]"
IP_VALUE = r"(?P<value_ip>[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2}\.[0-2]?[0-9]{1,2})"

IP_STR = r"(:?IP|ip|Ip)"
ID_STR = fr"(:?((Username|username|user_name|User|user)|(UserId|userid|userId))|(User)*{BLANK}*((ID|id|Id)|(Name|name)|(login|Login|Loging|Login as)|(account|Acccount))|role|root|telnet|아이디|계정)"

PREFIX = fr"(?:{DASH}|{DOUBLE_DASH})"
L_DELIMITER = fr"(?:{L_PAREN}|{L_BRACKET})"
R_DELIMITER = fr"(?:{R_PAREN}|{R_BRACKET})"

S_DELIMITER = fr"(?:{DASH}|{COLON}|{SLASH}|{DOUBLE_SLASH}?|{COMMA}|{BLANK}+|{EQUAL_SIGN}|({DASH}|{EQUAL_SIGN})+{BLANK}*{GT_SIGN}{BLANK}*|{VERB})"

PASSWD_STR = fr"((User|user|Default|default)?{BLANK}*([Pp]asswords|(Password|password|paasword|PASSWORD)|(Pw|pw)|(Pass|pass|PASS)|(Passwd|passwd)|(PWD|pwd|Pwd)|PIN|p/w)|-p|비밀번호|비번|패스워드|암호)[\"']*"
ID_PAIR = fr"{ID_STR}{S_DELIMITER}{ID_VALUE}"
SECRET_STR = r"(TOKEN|Token|token)|(secret|Secret)|(Key|KEY)|키|암호|암호화|토큰"

# PASSWD_PAIR = fr"({PASSWD_STR}{S_DELIMITER}{PASSWD_VALUE})|({PASSWD_STR}{BLANK}*{L_DELIMITER}{PASSWD_VALUE}{BLANK}*{R_DELIMITER})"
PASSWD_PAIR_1 = fr"{PASSWD_STR}{S_DELIMITER}{PASSWD_VALUE}"
PASSWD_PAIR_2 = fr"{PASSWD_STR}{BLANK}*{L_DELIMITER}{PASSWD_VALUE}{BLANK}*{R_DELIMITER}"
ID_PASSWD_PAIR = fr"{ID_STR}{S_DELIMITER}{PASSWD_STR}{S_DELIMITER}({ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}|{L_DELIMITER}{BLANK}*{ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}{BLANK}*{R_DELIMITER})|{ID_STR}{L_DELIMITER}{PASSWD_STR}{R_DELIMITER}{S_DELIMITER}{ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}"
SECRET_PAIR = fr"{SECRET_STR}{S_DELIMITER}{SECRET_VALUE}|{SECRET_STR}{BLANK}*{L_DELIMITER}{SECRET_VALUE}{BLANK}*{R_DELIMITER}"
SINGLE_STR_PAIR = fr"{ID_STR}{S_DELIMITER}{ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}|{ID_STR}{L_DELIMITER}{ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}{R_DELIMITER}"
# ID_PAIR_PASSWD_PAIR = fr"{ID_PAIR}{S_DELIMITER}{PASSWD_PAIR}|{PASSWD_PAIR}{S_DELIMITER}{ID_PAIR}"

IP_ID_PASSWD_TRIPLE = fr"({IP_STR}{S_DELIMITER}{ID_STR}{S_DELIMITER}{PASSWD_STR})*{BLANK}*{IP_VALUE}{S_DELIMITER}{ID_VALUE}{S_DELIMITER}{PASSWD_VALUE}"


def passwd_pair():
    if re.compile(PASSWD_PAIR_1):
        print(PASSWD_PAIR_1)
    if re.compile(PASSWD_PAIR_2):
        print(PASSWD_PAIR_2)

def ip_id_passwd_triple():
    if re.compile(IP_ID_PASSWD_TRIPLE):
        print(IP_ID_PASSWD_TRIPLE)


def main() -> int:
    passwd_pair()
    # ip_id_passwd_triple()
    return 0


if """__main__""" == __name__:
    sys.exit(main())
