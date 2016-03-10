#!/usr/bin/env python

# Intamixx

# Daemon to copy as-stats rrd files from nameservers

"""
Usage: ./rsync-rrd-daemon.py [stop|stop|status|restart]
"""

import sys, os, time, atexit
from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL, SIGINT, SIGTERM
import subprocess
import socket
import syslog
#from daemon import Daemon

class Daemon:
        """
        A generic daemon class.

        Usage: subclass the Daemon class and override the run() method
        """
        def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
                self.stdin = stdin
                self.stdout = stdout
                self.stderr = stderr
                self.pidfile = pidfile

        def daemonize(self):
                """
                do the UNIX double-fork magic
                """
                try: 
                        pid = os.fork() 
                        if pid > 0:
                                # exit first parent
                                sys.exit(0) 
                except OSError, e: 
                        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1)

                # decouple from parent environment
                os.chdir("/") 
                os.setsid() 
                os.umask(0) 

                # do second fork
                try: 
                        pid = os.fork() 
                        if pid > 0:
                                # exit from second parent
                                sys.exit(0) 
                except OSError, e: 
                        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1) 

                # redirect standard file descriptors
                sys.stdout.flush()
                sys.stderr.flush()
                si = file(self.stdin, 'r')
                so = file(self.stdout, 'a+')
                se = file(self.stderr, 'a+', 0)
                os.dup2(si.fileno(), sys.stdin.fileno())
                os.dup2(so.fileno(), sys.stdout.fileno())
                os.dup2(se.fileno(), sys.stderr.fileno())

                # write pidfile
                atexit.register(self.delpid)
                pid = str(os.getpid())
                file(self.pidfile,'w+').write("%s\n" % pid)

        def delpid(self):
                os.remove(self.pidfile)

        def start(self):
                """
                Start the daemon
                """
                # Check for a pidfile to see if the daemon already runs
                try:
                        pf = file(self.pidfile,'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if pid:
                        message = "pidfile %s already exist. Daemon already running?\n"
                        sys.stderr.write(message % self.pidfile)
                        sys.exit(1)

                # Start the daemon
                self.daemonize()
                self.run()

        def status(self):
                """
                Check the daemon status
                """
                # Check for a pidfile to see if the daemon already runs
                try:
                        pf = file(self.pidfile,'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if pid:
                        message = "pidfile %s already exist. Daemon already running.\n"
                        sys.stderr.write(message % self.pidfile)
                        sys.exit(1)
                else:
                        message = "Daemon not running?\n"
                        sys.stderr.write(message)
                        return # not an error in a restart

        def stop(self):
                """
                Stop the daemon
                """
                # Get the pid from the pidfile
                try:
                        pf = file(self.pidfile,'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if not pid:
                        message = "pidfile %s does not exist. Daemon not running?\n"
                        sys.stderr.write(message % self.pidfile)
                        return # not an error in a restart

                # Try killing the daemon process
                try:
                        while 1:
                                os.kill(pid, SIGTERM)
                                time.sleep(0.1)
                except OSError, err:
                        err = str(err)
                        if err.find("No such process") > 0:
                                if os.path.exists(self.pidfile):
                                        os.remove(self.pidfile)
                        else:
                                print str(err)
                                sys.exit(1)

        def restart(self):
                """
                Restart the daemon
                """
                self.stop()
                self.start()

        def run(self):
                """
                You should override this method when you subclass Daemon. It will be called after the process has been
                daemonized by start() or restart().
                """

class MyDaemon(Daemon):
        def run(self):
                rsync = 'rsync'
                host = ''
                port = ''
                timeNow = time.strftime("%Y%m%d%H%M%S")
                # locate rsync program
                cmd_exists = lambda x: any(os.access(os.path.join(path, x), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
                try:
                        result = cmd_exists('%s' % rsync)
                except e: logit('ERROR: Error locating %s' % rsync)
                if result == False:
                        logit('ERROR: Error %s not found' % rsync)

                while True:
                        digoutput = runDIGcmd("dig +short SRV _dns._udp.a.dns.centralnic.net | cut -d \" \" -f 4 | sed 's/.$//'")
                        nameserversA = digoutput.split('\n')
                        digoutput = runDIGcmd("dig +short SRV _dns._udp.b.dns.centralnic.net | cut -d \" \" -f 4 | sed 's/.$//'")
                        nameserversB = digoutput.split('\n')

                        nameservers = nameserversA + nameserversB
                        nameservers = [x for x in nameservers if x != '']

                        for host in nameservers:
                                port = "22"
                                port = int(port)

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

                                check = check_host(host, port)

                                logit("Launching %s rrd-> %s" % (rsync, host) )
                                runStr = "%s -4 -avz --include=\"*/\" --include=\"*.rrd\" --exclude=\"*\" -e \"ssh -4 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\" --delete --progress %s:/opt/AS-Stats-1.6/rrd/ /var/www/html/as-stats/%s/rrd/" % (rsync, host, host_short)

                                ( retCode, stdout, stderr ) = run(host,runStr,shell=True,timeout=1500)

                                retCode = int(retCode)
                                if (retCode == 0):
                                        print "%s\n%s" % (stdout, stderr)
                                        logit("Rsync Command exited normally %s: %s" % (host, retCode) )
                                else:
                                        print "%s\n%s" % (stdout, stderr)
                                        logit("Rsync Command failed %s: %s" % (host, retCode) )

def check_host(host, port):
       # Create a TCP socket
        logit("Attempting to connect to %s on port %s" % (host, port))
        s = socket.socket()
        s.settimeout(25)
        try:
                s.connect((host, port))
                logit("Connected to %s on port %s" % (host, port) )
                return True
        except socket.timeout:
                logit("Caught a connection timeout %s" % (host) )
                os._exit(1)
                return False
        except socket.error, e:
                logit("Connect Failed %s -> %s:%s" % (e, host, port) )
                os._exit(1)
                return False

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
    p=subprocess.Popen(args,shell=shell,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    logit("Running %s %s -> Pid [%d]" % (prog, host, p.pid) )
    if ( timeout != -1 ):
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
            logit("Killing %s %s -> Pid [%d]" % (prog, host, p.pid) )
            try: 
                kill(pid, SIGKILL)
            except OSError:
                pass
        return -2, '', ''
    return p.returncode, stdout, stderr

def get_process_children(pid):
    p=subprocess.Popen('/usr/bin/ps --no-headers -o pid --ppid %d' % pid,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return [int(p) for p in stdout.split()]

def runDIGcmd(cmd):
        try:
                proc=subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate()

                if stdout:
                        print "ret> ",proc.returncode
                        #print "OK> output ",stdout
                        return stdout
                if stderr:
                        logit("ret> ") % proc.returncode
                        logit("Error> error") % stderr.strip()
        except OSError as e:
            logit("OSError > %s ") % e.errno
            logit("OSError > %s ") % e.strerror
            logit("OSError > %s ") % e.filename
        except:
            logit ("Error > %s") % sys.exc_info()[0]

def logit(string):
        # log and prints a message
        #print "%s" % (string)
        syslog.syslog(syslog.LOG_INFO, "%s" % (string) )

if __name__ == "__main__":
        daemon = MyDaemon('/tmp/rsync-rrd.pid')
        if len(sys.argv) == 2:
                if 'start' == sys.argv[1]:
                        daemon.start()
                elif 'stop' == sys.argv[1]:
                        daemon.stop()
                elif 'restart' == sys.argv[1]:
                        daemon.restart()
                elif 'status' == sys.argv[1]:
                        daemon.status()
                else:
                        print "Unknown command"
                        sys.exit(2)
                sys.exit(0)
        else:
                print "usage: %s start|stop|status|restart" % sys.argv[0]
                sys.exit(2)
