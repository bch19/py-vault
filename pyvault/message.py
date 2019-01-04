import sys


def print_error(msg, rc):
    print(bcolors.FAIL + "ERROR! " + msg + bcolors.ENDC, file=sys.stderr)
    sys.exit(rc)

def print_success(msg):
    print( bcolors.OKGREEN + msg + bcolors.ENDC)
    sys.exit(0)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'