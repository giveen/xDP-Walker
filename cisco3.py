from easysnmp import Session, EasySNMPConnectionError, EasySNMPTimeoutError
import getopt
import sys
import csv
import os.path
import socket

def usage():
    print("""
    -d, --device        Device to scan
    -c, --community     SNMP community string
    -v, --verbose
    -f, --follow        Follow all the CDP neighbors
    -i, --ignore        Disable the Ignore List
    """)

def get_snmp_data(session, oid):
    try:
        system_items = session.walk(oid)
        return [(item.oid_index, item.value) for item in system_items]
    except Exception as excp:
        print(excp)
        return []

def cdp_cache_device_id(session):
    enterprises = '.1.3.6.1.4.1'
    cdp_cache_device_oid = '.9.9.23.1.2.1.1.6'
    return get_snmp_data(session, enterprises + cdp_cache_device_oid)

def cdp_cache_address(session):
    enterprises = '.1.3.6.1.4.1'
    cdp_cache_address_oid = '.9.9.23.1.2.1.1.4'
    return get_snmp_data(session, enterprises + cdp_cache_address_oid)

def cdp_remote_port(session):
    enterprises = '.1.3.6.1.4.1'
    cdp_remote_port_oid = '.9.9.23.1.2.1.1.7'
    return get_snmp_data(session, enterprises + cdp_remote_port_oid)

def cdp_remote_device_type(session):
    enterprises = '.1.3.6.1.4.1'
    cdp_remote_device_type_oid = '.9.9.23.1.2.1.1.8'
    return get_snmp_data(session, enterprises + cdp_remote_device_type_oid)

def if_name(session):
    if_long_name_oid = '1.3.6.1.2.1.2.2.1.2'
    return get_snmp_data(session, if_long_name_oid)

def combine(list1, list2, list3):
    tlist = []
    result_list = []

    for item1 in list1:
        for item2 in list2:
            if item1[0] == item2[0]:
                tlist.append([item1[0], item1[1], item2[1]])

    for titem in tlist:
        for item3 in list3:
            if item3[0] == titem[0]:
                result_list.append([titem[1], titem[2], item3[1]])

    return result_list

def host_lookup(n, i):
    info1 = info2 = info3 = info4 = info5 = info6 = ''

    try:
        an = socket.gethostbyaddr(i)
        if verbose:
            print(n + ' ' + i)
        if an[2][0] != i:
            info1 = 'hostname does not match ip in DNS'
            if verbose:
                print(info1)
                print(an)
        if an[0] == '':
            info2 = 'hostname not in DNS'
            if verbose:
                print(info2)
                print(an)
    except:
        info5 = 'ip does not exist in DNS - exception'

    try:
        ai = socket.gethostbyname(n)
        if ai != i:
            info3 = 'ip does not match name in DNS'
            if verbose:
                print(info3)
                print(ai)
        if ai[0] == '':
            info4 = 'hostname not in DNS'
            if verbose:
                print(info4)
                print(ai)
    except:
        info6 = 'hostname not in DNS - exception'

    info = '; '.join(filter(None, [info1, info2, info3, info4, info5, info6]))

    return info if info else None

def main():
    global community, device, ignore, verbose, follow, lookup

    print_differences = True
    print_failed = True

    scanned_list = []
    to_be_scanned_list = []
    scanned_list_full = []
    failed_to_connect = []

    try:
        session = Session(hostname=device, community=community, version=2)

        names = cdp_cache_device_id(session)
        ips = cdp_cache_address(session)
        remotetype = cdp_remote_device_type(session)
        int_name = if_name(session)

        inv = combine(names, ips, remotetype)

        for item in inv:
            if item not in scanned_list and item not in to_be_scanned_list:
                found = 0
                for ignore_item in IgnoreList:
                    if item[2].find(ignore_item) != -1:
                        found = 1
                if found == 0:
                    to_be_scanned_list.append(item)

    except Exception as excp:
        print(excp)

    count = 0
    max_count = 10

    if follow:
        while len(to_be_scanned_list) > 0:
            count += 1
            id = to_be_scanned_list.pop(0)
            name, org_name, lip, remote = id[0], id[1], id[2], id[3]
            error, desc, sys_device = '', '', ''

            try:
                inv = []
                if verbose:
                    print(f"Connecting to: {name} ({lip})")

                session = Session(hostname=name, community=community, version=2)
                description = session.get('.1.3.6.1.2.1.1.1.0')
                desc = description.value.replace('\r\n', ';')
                desc = desc.replace(',', '')
                desc = desc.encode('utf-8').strip()
                sys_device = session.get('.1.3.6.1.4.1.9.5.1.2.16.0')
                sys_device = sys_device.value.encode('utf-8').strip()

                names = cdp_cache_device_id(session)
                ips = cdp_cache_address(session)
                remotetype = cdp_remote_device_type(session)
                inv = combine(names, ips, remotetype)

            except EasySNMPConnectionError as excp:
                if verbose:
                    print("Failed to connect by Name, retrying with IP")
                error = "Failed to connect by Name"

                try:
                    inv = []
                    if verbose:
                        print(f"Connecting to: {lip}")

                    session = Session(hostname=lip, community=community, version=2)
                    description = session.get('.1.3.6.1.2.1.1.1.0')
                    desc = description.value.replace('\r\n', ';')
                    desc = desc.replace(',', '')
                    desc = desc.encode('utf-8').strip()
                    sys_device = session.get('.1.3.6.1.4.1.9.5.1.2.16.0')
                    sys_device = sys_device.value.encode('utf-8').strip()

                    names = cdp_cache_device_id(session)
                    ips = cdp_cache_address(session)
                    remotetype = cdp_remote_device_type(session)
                    inv = combine(names, ips, remotetype)

                except EasySNMPConnectionError as excp:
                    if verbose:
                        print("Failed to connect by IP")
                    error = "Failed to connect by Name and IP"
                    failed_to_connect.append([name, lip, remote, sys_device, desc, error])

                except EasySNMPTimeoutError as excp:
                    if verbose:
                        print("Timeout by Name")
                    error = "Timed out"
                    failed_to_connect.append([name, lip, remote, sys_device, desc, error])

            except EasySNMPTimeoutError as excp:
                if verbose:
                    print("Timeout by Name")
                error = "Timed out"
                failed_to_connect.append([name, lip, remote, sys_device, desc, error])

            info = host_lookup(name, lip)
            error = f"{error}; {info}" if error and info else error or None

            scanned_list_full.append([org_name, lip, remote, sys_device, desc, error])
            scanned_list.append([org_name, lip, remote])

            for item in inv:
                if item not in scanned_list and item not in to_be_scanned_list:
                    found = 0
                    for ignore_item in IgnoreList:
                        if item[2].find(ignore_item) != -1:
                            found = 1
                    if found == 0:
                        to_be_scanned_list.append(item)

            if verbose:
                print(f"Scanned: {len(scanned_list)} Left: {len(to_be_scanned_list)}")

        with open('current.csv', 'w') as csvfile:
            current = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            current.writerow(["name", "ip", "remote", "model", "description", "error"])
            for item in scanned_list_full:
                current.writerow(item)

        if os.path.isfile('baseline.csv'):
            pass
        else:
            with open('baseline.csv', 'w') as csvfile:
                baseline = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
                baseline.writerow(["name", "ip", "remote", "model", "description", "error"])
                for item in scanned_list_full:
                    baseline.writerow(item)

        with open('baseline.csv', 'r') as t1, open('current.csv', 'r') as t2:
            baseline = t1.readlines()
            current = t2.readlines()

        if print_differences:
            print("--- Differences in Baseline ---")
            for line in baseline:
                if line not in current:
                    print(line)

            print("--- Differences in Current ---")
            for line in current:
                if line not in baseline:
                    print(line)

        if print_failed:
            print("--- Failed to Connect to ---")
            for line in failed_to_connect:
                print(line)

    else:
        print(to_be_scanned_list)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:d:l:fiv",
                                   ['community=', 'device=', 'lookup=', 'ignore', 'verbose', 'follow'])
    except getopt.error:
        usage()

    community, device, ignore, verbose, follow, lookup = None, None, False, False, False, None

    for opt, val in opts:
        if opt in ('-c', '--community'):
            community = val
        if opt in ('-d', '--device'):
            device = val
        if opt in ('-i', '--ignore'):
            ignore = True
        if opt in ('-f', '--follow'):
            follow = True
        if opt in ('-v', '--verbose'):
            verbose = True
        if opt in ('-l', '--lookup'):
            lookup = val

    main()
