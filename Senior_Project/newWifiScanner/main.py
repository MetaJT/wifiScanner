# Wifi scanner

import os
import platform
import subprocess
import sys

class Bcolors:
    GREAT = "\033[0;32m" # green
    GOOD  = "\033[1;33m" # yellow
    FAIR = "\033[35m"    # magenta
    POOR = "\033[1;31m"  # red

def ensure_str(output):
    try:
        output = output.decode("utf8",errors='ignore')
    except UnicodeDecodeError:
        output = output.decode("utf16",errors='ignore')
    except AttributeError:
        pass
    return output


def rssi_to_quality(rssi):
    # Grabs RSSI and converts to a scale on 0 to 150
    return 2 * (rssi + 100)


def split_escaped(string, separator):
    """Split a string on separator, ignoring ones escaped by backslashes."""

    result = []
    current = ''
    escaped = False
    for char in string:
        if not escaped:
            if char == '\\':
                escaped = True
                continue
            elif char == separator:
                result.append(current)
                current = ''
                continue
        escaped = False
        current += char
    result.append(current)
    return result


class AccessPoint(dict):

    def __init__(self, ssid, bssid, quality, security):
        dict.__init__(self, ssid=ssid, bssid=bssid, quality=quality, security=security)

    def __getattr__(self, attr):
        return self.get(attr)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, d):
        self.__dict__ = d

    def __repr__(self):
        args = ", ".join(["{}={}".format(k, v) for k, v in self.items()])
        return "AccessPoint({})".format(args)


class WifiScanner(object):

    def __init__(self, device=""):
        self.device = device
        self.cmd = self.get_cmd()

    def get_cmd(self):
        raise NotImplementedError

    def parse_output(self, output):
        raise NotImplementedError

    def get_access_points(self):
        out = self.call_subprocess(self.cmd)
        results = self.parse_output(ensure_str(out))
        return results

    @staticmethod
    def call_subprocess(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, _) = proc.communicate()
        return out


class OSXWifiScanner(WifiScanner):

    def get_cmd(self):
        # In order to get BSSID we need to include sudo
        path = "sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
        cmd = "airport -s"
        return path + cmd

    # OSX Monterey doesn't output the BSSID unless you `sudo` which means the
    # old method using a regexp to match those lines fails.  Since the output
    # is column-formatted, we can use that instead and it works on both
    # Monterey-without-BSSID and pre-Monterey-with-BSSID.
    def parse_output(self, output):
        results = []
        security_start_index = False
        # First line looks like this (multiple whitespace truncated to fit.)
        # `\w+SSID BSSID\w+  RSSI CHANNEL HT CC SECURITY (auth/unicast/group)`
        # `       ^ ssid_end_index`
        # `                  ^ rssi_start_index`
        # `        ^       ^ bssid`
        for line in output.split("\n"):
            if line.strip().startswith("SSID BSSID"):
                security_start_index = line.index("SECURITY")
                ssid_end_index = line.index("SSID") + 4
                rssi_start_index = line.index("RSSI")
            elif line and security_start_index and 'IBSS' not in line:
                try:
                    ssid = line[0:ssid_end_index].strip()
                    bssid = line[ssid_end_index+1:rssi_start_index-1].strip()
                    rssi = line[rssi_start_index:rssi_start_index+4].strip()
                    security = line[security_start_index:]
                    ap = AccessPoint(ssid, bssid, rssi_to_quality(int(rssi)), security)
                    results.append(ap)
                except Exception as e:
                    msg = "Please provide the output of the error below this line at {}"
                    # print(msg.format("github.com/kootenpv/access_points/issues"))
                    # print(e)
                    # print("Line:")
                    # print(line)
                    # print("Output:")
                    # print(output)
        return results
    
def aps_to_dict(aps):
    return {ap['ssid'] + " " + ap['bssid']: ap['quality'] for ap in aps}

def get_scanner(device=""):
    # Just macOS systems for now
    operating_system = platform.system()
    if operating_system == 'Darwin':
        return OSXWifiScanner(device)

def sample(device=""):
    wifi_scanner = get_scanner(device)
    if not os.environ.get("PYTHON_ENV", False):
        aps = wifi_scanner.get_access_points()
    else:
        aps = [{"quality": 100, "bssid": "XX:XX:XX:XX:XX:84",
                "ssid": "X", "security": "XX"}]
    return aps_to_dict(aps)

def print_wifi_networks(networks):
    headers = ["SSID", "BSSID", "Quality", "Security"]
    networks = sorted(networks, key=lambda x:x['quality'], reverse=True)

    column_widths = [max(len(header), max(len(str(ap.get(header.lower()))) for ap in networks)) for header in headers]

    # Create the format string for formatting each row
    format_str = " | ".join(f"{{:<{width}}}" for width in column_widths)

    # Print the table headers
    print(format_str.format(*headers))
    print("-" * (sum(column_widths) + len(column_widths) * 3 - 2))

    # Print the data rows
    for ap in networks:
        if ap.get('quality') >= 70:
            color = Bcolors.GREAT
        elif ap.get('quality') >= 50:
            color = Bcolors.GOOD
        elif ap.get('quality') >= 30:
            color = Bcolors.FAIR
        else:
            color = Bcolors.POOR

        print(color + format_str.format(ap.get('ssid'), ap.get('bssid'), ap.get('quality'), ap.get('security')))

def main():

    device = [x for x in sys.argv[1:] if "-" not in x] or [""]
    device = device[0]
    wifi_scanner = get_scanner(device)
    access_points = wifi_scanner.get_access_points()
    if '-n' in sys.argv:
        print(len(access_points))
    else:
        print_wifi_networks(access_points)


if __name__ == '__main__':
    main()