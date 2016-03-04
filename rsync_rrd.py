#!/usr/bin/env python

# Msingh

"""
Wrapper script to rsync rrd files from the nameservers and optionally run rrdextractstats.pl

python rsync_rrd.py -h <nameserver> -d <timeout duration in seconds> -f -r
        -f   Copy the rrd files
        -r   Run the rrdextractstats.pl against the rrd files
"""

# Import required libraries, raise an exception if not installed
try:
        import syslog
        import time
        import getopt
        import sys
        import os
        import socket
except ImportError as e:
        print "\n%s is not installed. Please install it before running this script." % (e)
        exit (1)

from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL, SIGINT
from subprocess import PIPE, Popen

def run(host, args, cwd = None, shell = False, kill_tree = True, timeout = -1, env = None):
    '''
    Run a command with a timeout after which it will be forcibly
    killed (sigterm).
    '''
    prog = args.split(" ", 1)[0]
    class Alarm(Exception):
        pass
    def alarm_handler(signum, frame):
        raise Alarm
    p = Popen(args, shell = shell, cwd = cwd, stdout = PIPE, stderr = PIPE, env = env)
    logit("Running %s %s -> Pid [%d] " % (prog, host, p.pid) )
    if timeout != -1:
        signal(SIGALRM, alarm_handler)
        alarm(timeout)
    try:
        stdout, stderr = p.communicate()
        if timeout != -1:
            alarm(0)
    except Alarm:
        pids = [p.pid]
        if kill_tree:
            pids.extend(get_process_children(p.pid))
        for pid in pids:
            # process might have died before getting to this line
            # so wrap to avoid OSError: no such process
            logit("Killing %s %s -> Pid [%d] " % (prog, host, p.pid) )
            try: 
                kill(pid, SIGKILL)
            except OSError:
                pass
        return -2, '', ''
    return p.returncode, stdout, stderr

def get_process_children(pid):
    p = Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True,
              stdout = PIPE, stderr = PIPE)
    stdout, stderr = p.communicate()
    return [int(p) for p in stdout.split()]

def check_host(hostip, port):
        # Create a TCP socket
                s = socket.socket()
                s.settimeout(25)
                logit("Attempting to connect to %s on port %s" % (hostip, port) )
                try:
                        s.connect((hostip, port))
                        logit("Connected to %s on port %s" % (hostip, port) )
                        return True
                except socket.timeout:
                        logit("Caught a connection timeout %s" % (hostip) )
                        os._exit(1)
                        return False
                except socket.error, e:
                        logit("Connect Failed %s -> %s:%s" % (e, hostip, port) )
                        os._exit(1)
                        return False

def logit(string):
        # log and prints a message
        print "%s" % (string)
        syslog.syslog(syslog.LOG_INFO, "%s" % (string) )

def main(argv):
    host = ''
    duration = ''
    hostip = ''
    port = "22"
    rrdcopy = ''
    rrdstats = ''
    timeNow = time.strftime("%Y%m%d%H%M%S")

    try:
        opts, args = getopt.getopt(argv,"hc:d:fr",["host=","duration="])
    except getopt.GetoptError:
     print '%s -c <host: nameserver> -d <timeout in seconds> -f -r' % format(os.path.abspath(__file__))
     sys.exit(2)
    for opt, arg in opts:
     if opt == '-h':
        print '%s -c <host: nameserver> -d <timeout in seconds> -f -r' % format(os.path.abspath(__file__))
        sys.exit()
     elif opt in ("-c", "--host"):
        host = arg
     elif opt in ("-d", "--duration"):
        duration = arg
     elif opt in ("-r"):
        rrdstats = 'true'
     elif opt in ("-f"):
        rrdcopy = 'true'
    if not host or not duration:
        print '%s -c <host: nameserver> -d <timeout in seconds> -f -r' % format(os.path.abspath(__file__))
        sys.exit(1)
    if not rrdcopy and not rrdstats:
        print '%s -c <host: nameserver> -d <timeout in seconds> -f -r' % format(os.path.abspath(__file__))
        sys.exit(1)
    else:
        duration = int(duration)
        rrdextractstats_duration = (duration) * 3

    # locate rsync program
    cmd_exists = lambda x: any(os.access(os.path.join(path, x), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    try:
        result = cmd_exists('%s' % rsync)
    except e: sys.exit('ERROR: Error locating %s' % rsync)
    if result == False:
        sys.exit('ERROR: Error %s not found' % rsync)

    # check directory exists
    host_short = host.replace('.centralnic.net','')
    rrddirectory = '/var/www/html/as-stats/%s/rrd' % (host_short)
    result = os.path.exists('%s' % rrddirectory)
    if result == False:
        logit("Directory %s not Found" % rrddirectory)
        try:
                 os.makedirs('%s' % rrddirectory)
        except OSError:
                logit("Could not create rrd directory %s" % rrddirectory)
                sys.exit('ERROR: Could not create rrd directory %s' % rrddirectory)

    print "Host: %s  Duration: %s  RRDextractstats_Duration: %s\n" % (host, duration, rrdextractstats_duration)

    port = int(port)
    check = check_host(host, port)

    if rrdcopy:
       logit("Launching %s -> %s" % (rsync, host) )
       runStr = "%s -4 -avz  --include=\"*/\" --include=\"*.rrd\" --exclude=\"*\" -e \"ssh -4 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\" --delete --progress %s:/opt/AS-Stats-1.6/rrd/ /var/www/html/as-stats/%s/rrd/" % (rsync, host, host_short)

       print runStr
       ( retCode, stdout, stderr ) = run(host, runStr, shell = True, timeout = duration)

       retCode = int(retCode)
       if (retCode == 0):
           print "%s\n%s" % (stdout, stderr)
           logit("Rsync Command exited normally %s: %s" % (host, retCode) )
       else:
           print "%s\n%s" % (stdout, stderr)
           logit("Rsync Command failed %s: %s" % (host, retCode) )
           sys.exit(1)

    if rrdstats:
        logit("Launching RRDextractstats -> %s" % (host) )
        runStr = "/opt/AS-Stats-1.6/bin/rrd-extractstats.pl /var/www/html/as-stats/%s/rrd/ /var/www/html/as-stats/%s/knownlinks /var/www/html/as-stats/%s/asstats_day.txt" % (host_short, host_short, host_short)
        print runStr
        ( retCode, stdout, stderr ) = run(host, runStr, shell = True, timeout = rrdextractstats_duration)

        retCode = int(retCode)
        if (retCode == 0):
                print "%s\n%s" % (stdout, stderr)
                logit("RRD extract stats command exited normally %s: %s" % (host, retCode) )
                sys.exit(0)
        else:
                print "%s\n%s" % (stdout, stderr)
                logit("RRD extract stats command failed %s: %s" % (host, retCode) )
                sys.exit(1)

if __name__ == '__main__':
    rsync = 'rsync'
    main(sys.argv[1:])
