from tkinter import *
from tkinter import filedialog
import ipaddress
import xlrd

top = Tk()
top.title('MGMT and TOR Script Generator')


# Variables declared
mgmt_name_a = StringVar()
mgmt_name_b = StringVar()
tor_name_a = StringVar()
tor_name_b = StringVar()
mgmt_ip_a = StringVar()
mgmt_ip_b = StringVar()
tor_ip_a = StringVar()
tor_ip_b = StringVar()
vpc_a = StringVar()
vpc_b = StringVar()
stp_a = StringVar()
stp_b = StringVar()
uplink_a = StringVar()
uplink_b = StringVar()
udld_option_a = StringVar()
udld_option_b = StringVar()
lacp_mode_a = StringVar()
lacp_mode_b = StringVar()
lb_temp_a = StringVar()
lb_temp_b = StringVar()
router_temp = StringVar()
breakout_ports = StringVar()
ucs_domain_count = StringVar()
domain_name = StringVar()
dns_ips = StringVar()
ntp_ips = StringVar()
log_server = StringVar()
log_level = StringVar()
log_facility = StringVar()
# oob_name = StringVar()
# oob_id = StringVar()
# oob_network = StringVar()
# oob_gateway = StringVar()
# storage_name = StringVar()
# storage_id = StringVar()
# esx_name = StringVar()
# esx_id = StringVar()
# esx_network = StringVar()
# esx_gateway = StringVar()
# esx_vm_name = StringVar()
esx_ft_check = IntVar()
vc_ha_check = IntVar()
amp_ft_check = IntVar()
# esx_vm_id = StringVar()
# build_name = StringVar()
# build_id = StringVar()
# vc_ha_name = StringVar()
# vc_ha_id = StringVar()
# amp_name = StringVar()
# amp_id = StringVar()
# amp_network = StringVar()
# amp_gateway = StringVar()
# amp_vm_name = StringVar()
# amp_vm_id = StringVar()
# amp_vm_network = StringVar()
# amp_vm_gateway = StringVar()
# unused_name = StringVar()
# unused_id = StringVar()
community = StringVar()
customer_names = StringVar()
customer_ids = StringVar()
unified_in_names = StringVar()
unified_in_ids = StringVar()
unified_ex_names = StringVar()
unified_ex_ids = StringVar()
port_map_location = StringVar()


def write_hostname_and_features(**kwargs):
    kwargs['file'].write("hostname {}\n".format(kwargs['hostname']))
    if str(kwargs['file']).__contains__('MGMT'):
        kwargs['file'].write("\ncfs eth distribute\nfeature interface-vlan\nfeature hsrp\nfeature lacp\nfeature vpc\n")
    else:
        kwargs['file'].write("\ncfs eth distribute\nfeature lacp\nfeature vpc\n")
    if kwargs['udld'] != 'No':
        kwargs['file'].write("\nfeature udld\n" if kwargs['udld'] == "Normal" else "\nfeature udld\nudld aggressive\n")
    else:
        kwargs['file'].write("\n")


def write_banner(**kwargs):
    kwargs['file'].write("\nrole name default-role\n"
                         "description This is a system defined role and applies to all users.\n"
                         "username admin password 5 VMwar3!!  role network-admin\n")
    kwargs['file'].write("banner motd #\n***W A R N I N G***\nTHIS IS A PRIVATE COMPUTER SYSTEM.\n"
                         "This computer system including all related equipment, network devices,\n"
                         "are provided only for authorized use.\n"
                         "All computer systems may be monitored for all lawful purposes, including\n"
                         "those activities that are authorized for management of the system.\n"
                         "All information including personal information, stored or sent over this\n"
                         "system may be monitored.\n"
                         "Uses of this system, authorized or unauthorized, constitutes consent to\n"
                         "monitoring of this system.\nUnauthorized use may subject you to criminal prosecution.\n"
                         "WARNING: Unauthorized access to this system is forbidden and will be\nprosecuted by law.\n"
                         "By accessing this system, you agree that your actions may be monitored.\n#")


def write_ssh_settings(**kwargs):
    kwargs['file'].write("\nno feature ssh\nssh login-attempts 3\nssh key rsa 2048\nfeature ssh\n")


def write_domain_dns(**kwargs):
    kwargs['file'].write("\nno ip domain-lookup\nip domain-name {}\nip name-server {}"
                         .format(kwargs['domain'], str(kwargs['dns']).replace(',', ' ')))
    kwargs['file'].write(" use-vrf management\n" if str(kwargs['file']).__contains__('TOR') else "\n")
    kwargs['file'].write("vlan dot1Q tag native\ncopp profile strict\ny\n\n")


def get_vlans(**kwargs):
    unified_vlan_names = str(kwargs['names']).split(',')
    unified_vlan_ids = str(kwargs['ids']).split(',')
    vlans = list()
    count = 0
    for unified_vlan_name in unified_vlan_names:
        vlans.append(add_vlan(unified_vlan_name, unified_vlan_ids[count]))
        count += 1
    return vlans


def define_qos(**kwargs):
    if kwargs['unified'] != "":
        kwargs['file'].write("\nclass-map type qos match-any GOLD\nmatch cos 4\nmatch dscp 26\n"
                             "class-map type qos match-any SILVER\nmatch cos 2\nmatch dscp 16\n"
                             "class-map type qos match-any PLATINUM\nmatch cos 6\nmatch dscp 48\n"
                             "policy-map type qos NFS-DM-SET-QOS\nclass class-default\nset cos 2\nset dscp 16\n"
                             "policy-map type qos interface_qos_policy\nclass GOLD\nset qos-group 2\nclass PLATINUM\n"
                             "set qos-group 1\nclass SILVER\nset qos-group 3\n"
                             "policy-map type queuing system_queueing_policy\nclass type queuing c-out-q1\n"
                             "bandwidth percent 5\nclass type queuing c-out-q2\nbandwidth percent 10\n"
                             "class type queuing c-out-q3\nbandwidth percent 35\nclass type queuing c-out-q-default\n"
                             "bandwidth percent 50\nsystem qos\n"
                             "service-policy type queuing output system_queueing_policy\n")
    else:
        kwargs['file'].write("\nclass-map type qos match-any GOLD\n  match cos 4\n  match dscp 26\n"
                             "class-map type qos match-any PLATINUM\n  match cos 6\n  match dscp 48\n"
                             "policy-map type qos interface_qos_policy\n  class GOLD\n    set qos-group 2\n"
                             "  class PLATINUM\n set qos-group 1\npolicy-map type queuing system_queueing_policy\n"
                             "  class type queuing c-out-q1\n  bandwidth percent 5\n class type queuing c-out-q2\n"
                             "  bandwidth percent 10\n class type queuing c-out-q3\n bandwidth percent 0\n"
                             " class type queuing c-out-q-default\n  bandwidth percent 85\nsystem qos\n"
                             "  service-policy type queuing output system_queueing_policy\n")


def write_snmp_ntp(**kwargs):
    kwargs['file'].write("\nsnmp-server host {} traps version 2c {}\nsnmp-server enable traps\n"
                         .format(kwargs['logging_server'], kwargs['snmp_comm']))
    kwargs['file'].write("snmp-server community {} group network-operator\n".format(kwargs['snmp_comm']))
    for ntp_ip in kwargs['ntp'].split(','):
        kwargs['file'].write("ntp server {}".format(ntp_ip))
        kwargs['file'].write(" use-vrf management\n" if str(kwargs['file']).__contains__('TOR') else "\n")
    kwargs['file'].write("ntp source {}\n".format(kwargs['ip']))
    kwargs['file'].write("ntp master 8\n" if str(kwargs['file']).__contains__('MGMT-A') else "\n")


def add_vlan(*args):
    vlans = dict()
    vlans['name'] = args[0]
    vlans['id'] = args[1]
    try:
        vlans['network'] = args[2]
        vlans['gateway'] = args[3]
    except IndexError:
        vlans['network'] = ''
        vlans['gateway'] = ''
    return vlans


def write_route(**kwargs):
    kwargs['file'].write("\nno ip source-route\n")
    if str(kwargs['file']).__contains__('MGMT-A'):
        kwargs['file'].write("\nvrf context default\n   ip route 0.0.0.0/0 {}\n".format(kwargs['router_ip']))
    elif str(kwargs['file']).__contains__('MGMT-B'):
        kwargs['file'].write("\nvrf context default\n   ip route 0.0.0.0/0 {}\n".format(kwargs['mgmt_a']))
    elif str(kwargs['file']).__contains__('TOR'):
        kwargs['file'].write("\nvrf context management\n   ip route 0.0.0.0/0  {}\n".format(kwargs['mgmt_gateway']))


def compare_vlans(args, **kwargs):
    vlans = list()
    for key, value in kwargs['vlans'].items():
        if key in args:
            if isinstance(value, dict):
                vlans.append({"name": value['name'], 'id': value['id'],
                              'network': value['network'], 'gateway': value['gateway']})
            elif isinstance(value, list):
                for each_value in value:
                    vlans.append({'name': each_value['name'], 'id': each_value['id'],
                                  'network': each_value['network'], 'gateway': each_value['gateway']})
    return vlans


def write_l2_vlans_mgmt(**kwargs):
    list_of_vlans = ['system_mgmt_vlan', 'amp_storage_vlan', 'esx_mgmt_vlan',
                     'build_vlan', 'amp_mgmt_vlan', 'amp_vm_vlan', 'unused_vlan']
    verified_vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    for vlan in verified_vlans:
        kwargs['file'].write("\nvlan {}\n name {}\n".format(vlan['id'], vlan['name']))
    kwargs['file'].write("state suspend\n")


def write_l2_vlans_tor(**kwargs):
    list_of_vlans = ['esx_mgmt_vlan', 'esx_vm_vlan', 'esx_ft_vlan', 'build_vlan',
                     'vc_ha_vlan', 'amp_mgmt_vlan', 'amp_vm_vlan', 'amp_ft_vlan', 'unified_in_vlan', 'unified_ex_vlan',
                     'customer_vlan', 'unused_vlan']
    verified_vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    for vlan in verified_vlans:
        kwargs['file'].write("\nvlan {}\n name {}\n".format(vlan['id'], vlan['name']))
    kwargs['file'].write("state suspend\n")


def write_stp_vpc(**kwargs):
    kwargs['file'].write("\nno cdp enable\nspanning-tree port type edge bpduguard default\n"
                         "spanning-tree port type edge bpdufilter default\n"
                         "spanning-tree vlan 1-3967 priority {}\n".format(kwargs['stp']))
    kwargs['file'].write("\nvpc domain {}\npeer-switch\n".format(kwargs['vpc']))
    kwargs['file'].write("role priority 8192\n" if str(kwargs['file']).__contains__('A') else "role priority 16384\n")
    kwargs['file'].write("system-priority 8192\npeer-keepalive destination ")
    if str(kwargs['file']).__contains__('B'):
        kwargs['file'].write("{} source {}".format(kwargs['ips'][kwargs['pos']], kwargs['ips'][kwargs['pos']+1]))
    else:
        kwargs['file'].write("{} source {}".format(kwargs['ips'][kwargs['pos']+1], kwargs['ips'][kwargs['pos']]))
    kwargs['file'].write("\npeer-gateway\nno layer3 peer-router syslog\nauto-recovery\n"
                         "ipv6 nd synchronize\nip arp synchronize\n")


def svi_ip_address(**kwargs):
    network_ip = ipaddress.ip_network(kwargs['network'])
    ip_removal_list = [network_ip.network_address, network_ip.broadcast_address,
                       ipaddress.ip_address(kwargs['gateway'])]
    for ip in kwargs['ips']:
        ip_removal_list.append(ipaddress.ip_address(ip))
    ip_list = list(network_ip)
    for ip in ip_removal_list:
        if ip in ip_list:
            ip_list.remove(ip)
    if str(kwargs['file']).__contains__('A'):
        return str(ip_list[0])+"/"+str(network_ip.prefixlen)
    else:
        return str(ip_list[1])+"/"+str(network_ip.prefixlen)


def write_build_svi(**kwargs):
    dns = ipaddress.ip_address(str(kwargs['dns']).split(',')[0])
    dns_network = ipaddress.ip_network(str(dns) + '/24', strict=False)
    dns_gateway = dns_network.network_address+1 if dns != dns_network.network_address+1 \
        else dns_network.broadcast_address-1
    kwargs['file'].write("\ninterface vlan{}\n".format(kwargs['vlan']['id']))
    kwargs['file'].write(" description {}\n".format(kwargs['vlan']['name']))
    kwargs['file'].write(" no shutdown\n mtu 9216\n no ip redirects\n")
    kwargs['file'].write(" ip address {}\n".format(svi_ip_address(network=dns_network, gateway=dns_gateway,
                                                                  ips=kwargs['ips'], file=kwargs['file'])))
    kwargs['file'].write(" no ipv6 redirects\n hsrp version 2\n hsrp {}\n".format(kwargs['vlan']['id']))
    kwargs['file'].write("    authentication md5 key-string Vce12345\n    preempt\n")
    kwargs['file'].write("    priority 110\n" if str(kwargs['file']).__contains__('A') else "")
    kwargs['file'].write("    ip {}\n".format(dns_gateway))


def write_svi(**kwargs):
    list_of_vlans = ['system_mgmt_vlan', 'esx_mgmt_vlan',
                     'amp_mgmt_vlan', 'amp_vm_vlan']
    verified_vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    for vlan in verified_vlans:
        kwargs['file'].write("\ninterface vlan{}\n".format(vlan['id']))
        kwargs['file'].write(" description {}\n".format(vlan['name']))
        kwargs['file'].write(" no shutdown\n   mtu 9216\n  no ip redirects\n")
        kwargs['file'].write(" ip address {}\n".format(svi_ip_address(network=vlan['network'], gateway=vlan['gateway'],
                                                                      ips=kwargs['switch_ips'], file=kwargs['file'])))
        kwargs['file'].write(" no ipv6 redirects\n hsrp version 2\n hsrp {}\n".format(vlan['id']))
        kwargs['file'].write("    authentication md5 key-string Vce12345\n    preempt\n")
        kwargs['file'].write("    priority 110\n" if str(kwargs['file']).__contains__('A') else "")
        kwargs['file'].write("    ip {}\n".format(vlan['gateway']))
    write_build_svi(vlan=kwargs['vlans']['build_vlan'], ips=kwargs['switch_ips'], dns=kwargs['dns'], file=kwargs['file'])


def get_vlan_ids(**kwargs):
    vlan_ids = ""
    for vlan in kwargs['vlans']:
        vlan_ids += vlan['id'] + ","
    return vlan_ids[:-1]


def write_customer_port_channel(**kwargs):
    kwargs['file'].write("\ninterface port-channel{}\n".format(kwargs['port_channel_num']))
    kwargs['file'].write(" description To Customer Uplink\n shutdown\n switchport\n switchport mode trunk\n")
    kwargs['file'].write(" switchport trunk allowed vlan {}\n".format(get_vlan_ids(vlans=kwargs['vlans'])))
    kwargs['file'].write(" spanning-tree port type network\n")
    kwargs['file'].write(" mtu 9216\n" if str(kwargs['file']).__contains__('TOR') else "")
    kwargs['file'].write(" speed {}000\n".format(kwargs['uplink_speed']))
    kwargs['file'].write(" no negotiate auto\n" if str(kwargs['file']).__contains__('TOR') else "")
    kwargs['file'].write(" vpc {}\n".format(kwargs['port_channel_num']))


def write_vpc_port_channel(**kwargs):
    kwargs['file'].write("\ninterface port-channel{}\n".format(kwargs['port_channel_num']))
    if str(kwargs['file']).__contains__('MGMT'):
        if str(kwargs['file']).__contains__('A'):
            kwargs['file'].write(" description To VPC PEER Nexus 31108TC-V-B\n")
        else:
            kwargs['file'].write(" description To VPC PEER Nexus 31108TC-V-A\n")
    else:
        if str(kwargs['file']).__contains__('A'):
            kwargs['file'].write(" description To VPC-PEER-9336C-FX2-B\n")
        else:
            kwargs['file'].write(" description To VPC-PEER-9336C-FX2-A\n")
    kwargs['file'].write(" switchport\n switchport mode trunk\n spanning-tree port type network\n speed 100000\n")
    kwargs['file'].write(" no negotiate auto\n vpc peer-link\n")


def write_port_channels(**kwargs):
    if str(kwargs['file']).__contains__('MGMT'):
        customer_port_channel_num = 5
        vpc_port_channel_num = 10
        list_of_vlans = ['system_mgmt_vlan']
        vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    else:
        customer_port_channel_num = 1
        vpc_port_channel_num = 50
        list_of_vlans = ['esx_mgmt_vlan', 'esx_vm_vlan',
                         'amp_mgmt_vlan', 'amp_vm_vlan', 'customer_vlan']
        vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    write_customer_port_channel(uplink_speed=kwargs['uplink_speed'], port_channel_num=customer_port_channel_num,
                                vlans=vlans, file=kwargs['file'])
    write_vpc_port_channel(port_channel_num=vpc_port_channel_num, file=kwargs['file'])


def write_ucs_port_channels(**kwargs):
    list_of_vlans = ['esx_mgmt_vlan', 'esx_vm_vlan', 'build_vlan', 'unified_in_vlan',
                     'esx_ft_vlan', 'customer_vlan']
    fi_list = ['FI 1A', 'FI 1B', 'FI 2A', 'FI 2B', 'FI 3A', 'FI 3B']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    ucs_num = int(kwargs['ucs_domain_num']) * 2
    channel_num = 101
    for fi in fi_list[:ucs_num]:
        kwargs['file'].write("\ninterface port-channel{}\n".format(channel_num))
        kwargs['file'].write(" description To {}\n".format(fi))
        kwargs['file'].write(" switchport\n switchport mode trunk\n"
                             " switchport trunk allowed vlan {}\n".format(get_vlan_ids(vlans=vlans)))
        kwargs['file'].write(" spanning-tree port type edge trunk\n mtu 9216\n"
                             " service-policy type qos input interface_qos_policy\n vpc {}\n".format(channel_num))
        channel_num += 1


def write_unified_port_channels(**kwargs):
    port_channel_num = 201
    list_of_vlans = ['unified_in_vlan', 'unified_ex_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    storage_dpes = ['A', 'B']
    for storage_dpe in storage_dpes:
        kwargs['file'].write("\ninterface port-channel{}\n".format(port_channel_num))
        kwargs['file'].write(" description To NFS {}\n".format(storage_dpe))
        kwargs['file'].write(" switchport\n switchport mode trunk\n"
                             " switchport trunk allowed vlan {}\n".format(get_vlan_ids(vlans=vlans)))
        kwargs['file'].write(" spanning-tree port type edge trunk\n mtu 9216\n"
                             " service-policy type qos input NFS-DM-SET-QOS\n vpc {}\n".format(port_channel_num))
        port_channel_num += 1


def get_eth_names(**kwargs):
    eth_ports = []
    if str(kwargs['file']).__contains__('A'):
        low_row, high_row = 2, 4
    else:
        low_row, high_row = 8, 10
    for i in range(0, kwargs['limit']):
        for j in range(low_row, high_row):
            if kwargs['sheet'].cell_value(j, i) != "":
                eth_ports.append(kwargs['sheet'].cell_value(j, i))
            else:
                if kwargs['sheet'].cell_value(j-1, i) != "" or kwargs['sheet'].cell_value(j+1, i) != "":
                    eth_ports.append(kwargs['sheet'].cell_value(j, i))
    kwargs['cell_router_temp'] = int(kwargs['cell_router_temp'])
    kwargs['lb_temp'] = int(kwargs['lb_temp'])
    if kwargs['cell_router_temp'] < 99:
        eth_ports[kwargs['cell_router_temp']] = 'Cell_Temp_Link'
    eth_ports[kwargs['lb_temp']] = 'LB_Temp_Link'
    return eth_ports


def write_mgmt_port(**kwargs):
    list_of_vlans = ['system_mgmt_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    if len(vlans) == 1:
        kwargs['file'].write(" switchport access vlan {}\n".format(vlans[0]['id']))
    kwargs['file'].write(" spanning-tree port type edge\n no shutdown\n")


def write_amp_nas_port(**kwargs):
    list_of_vlans = ['amp_storage_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    if len(vlans) == 1:
        kwargs['file'].write(" switchport access vlan {}\n".format(vlans[0]['id']))
    kwargs['file'].write(" spanning-tree port type edge\n mtu 9216\n speed 10000\n"
                         " vpc orphan-port suspend\n no shutdown\n")


def write_cimc_port(**kwargs):
    list_of_vlans = ['system_mgmt_vlan', 'amp_storage_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    kwargs['file'].write(" switchport mode trunk\n")
    kwargs['file'].write(" switchport trunk allowed vlan {}\n".format(get_vlan_ids(vlans=vlans)))
    kwargs['file'].write(" spanning-tree port type edge trunk\n mtu 9216\n speed 10000\n"
                         " vpc orphan-port suspend\n no shutdown\n")


def write_cell_router_temp_port(**kwargs):
    kwargs['file'].write(" no switchport\n ip address 192.168.10.2/24\n no shutdown\n")


def write_lb_temp_port(**kwargs):
    list_of_vlans = ['esx_mgmt_vlan', 'build_vlan', 'amp_mgmt_vlan', 'amp_vm_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    kwargs['file'].write(" switchport mode trunk\n switchport trunk allowed vlan {}\n"
                         " no shutdown\n".format(get_vlan_ids(vlans=vlans)))


def write_customer_port(**kwargs):
    kwargs['file'].write(" shutdown\n"
                         " spanning-tree port type network\n "
                         " channel-group {} ".format(kwargs['port_channel_num']))
    kwargs['file'].write("mode active\n" if kwargs['lacp_mode'] == 'LACP' else "mode on\n")


def write_peer_port(**kwargs):
    kwargs['file'].write(" channel-group {} mode active\n no shutdown\n".format(kwargs['port_channel_num']))


def write_mgmt_interface(**kwargs):
    kwargs['file'].write("\ninterface mgmt0\n description {}\n vrf member management\n"
                         " ip address {}\n no shutdown\n".format(kwargs['description'], kwargs['ip']))


def write_empty_port(**kwargs):
    list_of_vlans = ['unused_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    kwargs['file'].write(" shutdown\n switchport access vlan {}\n".format(get_vlan_ids(vlans=vlans)))


def write_interfaces_mgmt(**kwargs):
    port_map_workbook = xlrd.open_workbook(kwargs['port_map'])
    sheet = port_map_workbook.sheet_by_name('31108TC-V')
    eth_names = get_eth_names(lb_temp=int(kwargs['lb_temp'])-1, cell_router_temp=int(kwargs['cell_router_temp'])-1,
                              limit=30, sheet=sheet, file=kwargs['file'])
    count = 1
    for eth in eth_names:
        kwargs['file'].write("\ninterface ethernet 1/{}\n".format(count))
        kwargs['file'].write(" description {}\n".format(eth) if str(eth) != "" else "")
        if count == int(kwargs['cell_router_temp']) and str(kwargs['file']).__contains__('A'):
            write_cell_router_temp_port(vlans=kwargs['vlans'], file=kwargs['file'])
        elif count == int(kwargs['lb_temp']) and str(kwargs['file']).__contains__('A'):
            write_lb_temp_port(vlans=kwargs['vlans'], file=kwargs['file'])
        elif str(eth).__contains__('M0') or str(eth).__contains__('C0'):
            write_mgmt_port(vlans=kwargs['vlans'], file=kwargs['file'])
        elif str(eth).__contains__('DPE'):
            write_amp_nas_port(vlans=kwargs['vlans'], file=kwargs['file'])
        elif str(eth).__contains__('C2'):
            write_cimc_port(vlans=kwargs['vlans'], file=kwargs['file'])
        elif str(eth).__contains__('Uplink'):
            write_customer_port(port_channel_num=5, lacp_mode=kwargs['lacp_mode'], file=kwargs['file'])
        elif str(eth).__contains__('31108'):
            write_peer_port(port_channel_num=10, file=kwargs['file'])
        else:
            write_empty_port(vlans=kwargs['vlans'], file=kwargs['file'])
        count += 1
    if str(kwargs['file']).__contains__('A'):
        write_mgmt_interface(description='31108TC-V 1B-00:M0', ip='192.168.1.1/24', file=kwargs['file'])
    else:
        write_mgmt_interface(description='31108TC-V 1A-00:M0', ip='192.168.1.2/24', file=kwargs['file'])


def write_port(**kwargs):
    kwargs['file'].write("channel-group {} mode active\n".format(kwargs['port_channel_num']))
    kwargs['file'].write("spanning-tree port type edge trunk\nno shutdown\n")


def write_cimc_port_tor(**kwargs):
    list_of_vlans = ['build_vlan', 'amp_mgmt_vlan', 'amp_vm_vlan', 'vc_ha_vlan', 'amp_ft_vlan']
    vlans = compare_vlans(list_of_vlans, vlans=kwargs['vlans'])
    kwargs['file'].write(" switchport\n switchport mode trunk\n"
                         " switchport trunk allowed {}\n".format(get_vlan_ids(vlans=vlans)))
    kwargs['file'].write("  spanning-tree port type edge trunk\n mtu 9216\n speed 10000\n vpc orphan-port suspend\n"
                         " no shutdown\n")


def write_breakout_port(**kwargs):
    eth_names = str(kwargs['eth']).split('\n')
    if len(eth_names) < 4:
        for i in range(len(eth_names), 4):
            eth_names.append('')
    for port in range(0, 4):
        kwargs['file'].write("\ninterface ethernet 1/{}/{}\n".format(kwargs['count'], port+1))
        kwargs['file'].write(" description {}\n".format(eth_names[port]))
        eth = str(eth_names[port])
        if str(eth).__contains__('C2'):
            write_cimc_port_tor(vlans=kwargs['vlans'], file=kwargs['file'])
        elif str(eth).__contains__('ax') or str(eth).__contains__('Unity'):
            if str(eth).__contains__('A'):
                write_port(port_channel_num=201, file=kwargs['file'])
            else:
                write_port(port_channel_num=202, file=kwargs['file'])
        elif str(eth).__contains__('Uplink'):
            write_customer_port(port_channel_num=1, lacp_mode=kwargs['lacp_mode'], file=kwargs['file'])
        else:
            write_empty_port(vlans=kwargs['vlans'], file=kwargs['file'])


def write_interfaces_tor(**kwargs):
    port_map_workbook = xlrd.open_workbook(kwargs['port_map'])
    sheet = port_map_workbook.sheet_by_name('9336C-FX2')
    eth_names = get_eth_names(lb_temp=int(kwargs['lb_temp'])-1, cell_router_temp=int(kwargs['cell_router_temp'])-1,
                              limit=18, sheet=sheet, file=kwargs['file'])
    count = 1
    dividing_factor = ""
    if ',' in kwargs['breakout_ports_num']:
        dividing_factor = ','
    elif '-' in kwargs['breakout_ports_num']:
        dividing_factor = '-'
    breakout = str(kwargs['breakout_ports_num']).split(dividing_factor)
    breakout_port_list = range(int(breakout[0]), int(breakout[1]) + 1)
    kwargs['file'].write("\ninterface breakout module 1 port {}-{} map 10g-4x\n".format(breakout_port_list[0],
                                                                                        breakout_port_list[-1]))
    for eth in eth_names:
        if count not in breakout_port_list:
            kwargs['file'].write("\ninterface ethernet 1/{}\n".format(count))
            kwargs['file'].write(" description {}\n".format(eth) if str(eth) != "" else "")
            if count == int(kwargs['lb_temp']) and str(kwargs['file']).__contains__('A'):
                write_lb_temp_port(vlans=kwargs['vlans'], file=kwargs['file'])
            elif str(eth).__contains__('6454') or str(eth).__contains__('6332'):
                if str(eth).__contains__('1A'):
                    write_port(port_channel_num=101, file=kwargs['file'])
                elif str(eth).__contains__('1B'):
                    write_port(port_channel_num=102, file=kwargs['file'])
                elif str(eth).__contains__('1C') or str(eth).__contains__('2A'):
                    write_port(port_channel_num=103, file=kwargs['file'])
                elif str(eth).__contains__('1D') or str(eth).__contains__('2B'):
                    write_port(port_channel_num=104, file=kwargs['file'])
                elif str(eth).__contains__('1E') or str(eth).__contains__('3A'):
                    write_port(port_channel_num=103, file=kwargs['file'])
                elif str(eth).__contains__('1F') or str(eth).__contains__('3B'):
                    write_port(port_channel_num=104, file=kwargs['file'])
            elif str(eth).__contains__('C2'):
                write_cimc_port_tor(vlans=kwargs['vlans'], file=kwargs['file'])
            elif str(eth).__contains__('ax') or str(eth).__contains__('Unity'):
                if str(eth).__contains__('A'):
                    write_port(port_channel_num=201, file=kwargs['file'])
                else:
                    write_port(port_channel_num=202, file=kwargs['file'])
            elif str(eth).__contains__('Uplink'):
                write_customer_port(port_channel_num=1, lacp_mode=kwargs['lacp_mode'], file=kwargs['file'])
            elif str(eth).__contains__('9336'):
                write_peer_port(port_channel_num=50, file=kwargs['file'])
            else:
                write_empty_port(vlans=kwargs['vlans'], file=kwargs['file'])
        else:
            write_breakout_port(count=count, eth=eth, lacp_mode=kwargs['lacp_mode'],
                                vlans=kwargs['vlans'], file=kwargs['file'])
        count += 1
    subnet_mask = str(kwargs['vlans']['system_mgmt_vlan']['network']).split('/')[1]
    if str(kwargs['file']).__contains__('A'):
        write_mgmt_interface(description='31108TC-V 1A-01:02',
                             ip=str(kwargs['ips'][2])+'/'+subnet_mask, file=kwargs['file'])
    else:
        write_mgmt_interface(description='31108TC-V 1B-01:02',
                             ip=str(kwargs['ips'][3])+'/'+subnet_mask, file=kwargs['file'])


def write_log_server(**kwargs):
    level = ''.join(filter(lambda num: num.isdigit(), kwargs['logging_level']))
    use_vrf = 'default' if str(kwargs['file']).__contains__('MGMT') else 'management'
    kwargs['file'].write("\nline console\n  exec-timeout 5\nline vty\n session-limit 5\n  exec-timeout 5\n"
                         "ip tcp path-mtu-discovery\n")
    kwargs['file'].write("\nlogging logfile messages {} size 16384\nlogging server {} {} use-vrf {} "
                         "facility {}\n".format(level, kwargs['logging_server'],
                                                level, use_vrf, kwargs['logging_facility']))
    if str(kwargs['file']).__contains__('MGMT'):
        kwargs['file'].write("logging source-interface Vlan{}\n".format(kwargs['vlan_id']))
    kwargs['file'].write("\nlogging timestamp milliseconds\nno logging monitor\nno logging console\n")


def write_ntp_loopbacks(**kwargs):
    ntp_ip_list = str(kwargs['ntp']).split(',')
    count = 0
    for ntp in ntp_ip_list:
        kwargs['file'].write("\ninterface loopback{}\n".format(count))
        kwargs['file'].write(" ip address {}/32\n".format(ntp))


def submit():
    file3a = open("MGMT-A.txt", 'w+')
    file3b = open("MGMT-B.txt", 'w+')
    file9a = open("TOR-A.txt", 'w+')
    file9b = open("TOR-B.txt", 'w+')
    files = [file3a, file3b, file9a, file9b]
    hostnames = [mgmt_name_a.get(), mgmt_name_b.get(), tor_name_a.get(), tor_name_b.get()]
    ips = [mgmt_ip_a.get(), mgmt_ip_b.get(), tor_ip_a.get(), tor_ip_b.get(), '192.168.1.1', '192.168.1.2']
    udld_mgmt = udld_option_a.get()
    udld_tor = udld_option_b.get()
    domain = domain_name.get()
    dns = dns_ips.get()
    logging_server = log_server.get()
    logging_level = log_level.get()
    logging_facility = log_facility.get()
    snmp_comm = community.get()
    stp_mgmt = stp_a.get()
    stp_tor = stp_b.get()
    vpc_mgmt = vpc_a.get()
    vpc_tor = vpc_b.get()
    uplink_speed_mgmt = uplink_a.get()
    uplink_speed_tor = uplink_b.get()
    vlans = dict()
    ntp = ntp_ips.get()
    ucs_domain_num = ucs_domain_count.get()
    port_map = port_map_location.get()
    cell_router_temp = router_temp.get()
    lb_temp_mgmt = lb_temp_a.get()
    lb_temp_tor = lb_temp_b.get()
    lacp_mode_mgmt = lacp_mode_a.get()
    lacp_mode_tor = lacp_mode_b.get()
    breakout_ports_num = breakout_ports.get()

    if bool(oob_name.get()):
        vlans['system_mgmt_vlan'] = add_vlan(oob_name.get(), oob_id.get(), oob_network.get(), oob_gateway.get())
    if bool(storage_name.get()):
        vlans['amp_storage_vlan'] = add_vlan(storage_name.get(), storage_id.get())
    if bool(esx_name.get()):
        vlans['esx_mgmt_vlan'] = add_vlan(esx_name.get(), esx_id.get(), esx_network.get(), esx_gateway.get())
    if bool(esx_vm_name.get()):
        vlans['esx_vm_vlan'] = add_vlan(esx_vm_name.get(), esx_vm_id.get())
    if bool(build_name.get()):
        vlans['build_vlan'] = add_vlan(build_name.get(), build_id.get())
    if bool(amp_name.get()):
        vlans['amp_mgmt_vlan'] = add_vlan(amp_name.get(), amp_id.get(), amp_network.get(), amp_gateway.get())
    if bool(amp_vm_name.get()):
        vlans['amp_vm_vlan'] = add_vlan(amp_vm_name.get(), amp_vm_id.get(),
                                        amp_vm_network.get(), amp_vm_gateway.get())
    if vc_ha_check.get() == 1:
        vlans['vc_ha_vlan'] = add_vlan(vc_ha_name.get(), vc_ha_id.get())
    if amp_ft_check.get() == 1:
        vlans['amp_ft_vlan'] = add_vlan(amp_ft_name.get(), amp_ft_id.get())
    if esx_ft_check.get() == 1:
        vlans['esx_ft_vlan'] = add_vlan(esx_ft_name.get(), esx_ft_id.get())
    vlans['unified_in_vlan'] = get_vlans(names=unified_in_names.get(), ids=unified_in_ids.get()) \
        if bool(unified_in_names.get()) else ""
    vlans['unified_ex_vlan'] = get_vlans(names=unified_ex_names.get(), ids=unified_ex_ids.get()) \
        if bool(unified_ex_names.get()) else ""
    if bool(customer_names.get()):
        vlans['customer_vlan'] = get_vlans(names=customer_names.get(), ids=customer_ids.get())
    if bool(unused_name.get()):
        vlans['unused_vlan'] = add_vlan(unused_name.get(), unused_id.get())
    count = 0
    unified = ""
    if vlans['unified_in_vlan'] != '' or vlans['unified_ex_vlan'] != '':
        unified = " "
    for file in files:
        udld = udld_mgmt if 'MGMT' in file.name else udld_tor
        write_hostname_and_features(hostname=hostnames[count], udld=udld, file=file)
        write_banner(file=file)
        write_ssh_settings(file=file)
        write_domain_dns(domain=domain, dns=dns, file=file)
        define_qos(unified=unified, file=file) if "TOR" in file.name else ""
        write_snmp_ntp(logging_server=logging_server, snmp_comm=snmp_comm, ntp=ntp, ip=ips[count], file=file)
        write_route(router_ip='192.168.10.1', mgmt_gateway=vlans['system_mgmt_vlan']['gateway'],
                    mgmt_a=ips[0], file=file)
        write_l2_vlans_mgmt(vlans=vlans, file=file) if 'MGMT' in file.name \
            else write_l2_vlans_tor(vlans=vlans, file=file)
        if 'MGMT' in file.name:
            stp = stp_mgmt
            vpc = vpc_mgmt
            pos = 4
        else:
            stp = stp_tor
            vpc = vpc_tor
            pos = 2
        write_stp_vpc(pos=pos, ips=ips, stp=stp, vpc=vpc, file=file)
        if 'MGMT' in file.name:
            write_svi(dns=dns, switch_ips=ips, vlans=vlans, file=file)
        uplink_speed = uplink_speed_mgmt if 'MGMT' in file.name else uplink_speed_tor
        write_port_channels(uplink_speed=uplink_speed, vlans=vlans, file=file)
        if 'TOR' in file.name:
            write_ucs_port_channels(ucs_domain_num=ucs_domain_num, vlans=vlans, file=file)
            if unified != "":
                write_unified_port_channels(vlans=vlans, file=file)
        if 'MGMT' in file.name:
            write_interfaces_mgmt(cell_router_temp=cell_router_temp, lb_temp=lb_temp_mgmt,
                                  port_map=port_map, lacp_mode=lacp_mode_mgmt, vlans=vlans, file=file)
            if 'A' in file.name:
                write_ntp_loopbacks(ntp=ntp, file=file)
        else:
            write_interfaces_tor(cell_router_temp=100, lb_temp=lb_temp_tor, breakout_ports_num=breakout_ports_num,
                                 port_map=port_map, lacp_mode=lacp_mode_tor, ips=ips, vlans=vlans, file=file)
        write_log_server(logging_server=logging_server, logging_level=logging_level,
                         logging_facility=logging_facility, vlan_id=vlans['system_mgmt_vlan']['id'], file=file)
        count += 1
    for file in files:
        file.close()


class EntryWithPlaceholder(Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", color='grey'):
        super().__init__(master)

        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self['fg']

        self.bind("<FocusIn>", self.foc_in)
        self.bind("<FocusOut>", self.foc_out)

        self.put_placeholder()

    def put_placeholder(self):
        self.insert(0, self.placeholder)
        self['fg'] = self.placeholder_color

    def foc_in(self, *args):
        if self['fg'] == self.placeholder_color:
            self.delete('0', 'end')
            self['fg'] = self.default_fg_color

    def foc_out(self, *args):
        if not self.get():
            self.put_placeholder()


udld_options = ['No', 'Normal', 'Aggressive']
lacp_modes = ['LACP', 'On']
log_levels = ['Emergency(0)', 'Alert(1)', 'Critical(2)',
              'Error(3)', 'Warning(4)', 'Notice(5)', 'Informational(6)', 'Debug(7)']
log_facilities = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
ucs_domain_nums = list(range(1, 4))
port_nums = list(range(1, 55))

Label(top, text="######################################## MGMT/N3K Switch ##################################",
      font=('Times New Roman', 10, 'bold'), fg='Green').grid(row=0, column=0, sticky=E, columnspan=4)
Label(top, text="######################################## TOR/N9K Switch ##################################",
      font=('Times New Roman', 10, 'bold'), fg='Blue').grid(row=0, column=4, sticky=E, columnspan=4)
# Hostnames
Label(top, text="Switch-A Hostname:", relief=RIDGE, width=22, fg='Green').grid(row=1, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=mgmt_name_a).grid(row=1, column=1)
Label(top, text="Switch-B Hostname:", relief=RIDGE, width=22, fg='Green').grid(row=1, column=2, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=mgmt_name_b).grid(row=1, column=3)
Label(top, text="Switch-A Hostname:", relief=RIDGE, width=22, fg='Blue').grid(row=1, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=tor_name_a).grid(row=1, column=5)
Label(top, text="Switch-B Hostname:", relief=RIDGE, width=22, fg='Blue').grid(row=1, column=6, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=tor_name_b).grid(row=1, column=7)

# IP Addresses
Label(top, text="Switch-A IP Address:", relief=RIDGE, width=22, fg='Green').grid(row=2, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=mgmt_ip_a).grid(row=2, column=1)
Label(top, text="Switch-B IP Address:", relief=RIDGE, width=22, fg='Green').grid(row=2, column=2, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=mgmt_ip_b).grid(row=2, column=3)
Label(top, text="Switch-A IP Address:", relief=RIDGE, width=22, fg='Blue').grid(row=2, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=tor_ip_a).grid(row=2, column=5)
Label(top, text="Switch-B IP Address:", relief=RIDGE, width=22, fg='Blue').grid(row=2, column=6, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=tor_ip_b).grid(row=2, column=7)

# vPC Domain ID
Label(top, text="vPC Domain ID:", relief=RIDGE, width=22, fg='Green').grid(row=3, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=vpc_a).grid(row=3, column=1)
Label(top, text="vPC Domain ID:", relief=RIDGE, width=22, fg='Blue').grid(row=3, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=vpc_b).grid(row=3, column=5)

# STP Priorities
Label(top, text="STP Priority:", relief=RIDGE, width=22, fg='Green').grid(row=3, column=2, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=stp_a).grid(row=3, column=3)
Label(top, text="STP Priority:", relief=RIDGE, width=22, fg='Blue').grid(row=3, column=6, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=stp_b).grid(row=3, column=7)

# Uplink Speed
Label(top, text="Uplink Speed(in G):", relief=RIDGE, width=22, fg='Green').grid(row=4, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=uplink_a).grid(row=4, column=1)
Label(top, text="Uplink Speed(in G):", relief=RIDGE, width=22, fg='Blue').grid(row=4, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=uplink_b).grid(row=4, column=5)

# UDLD
Label(top, text="UDLD:", relief=RIDGE, width=22, fg='Green').grid(row=4, column=2, sticky=E)
udld_option_a.set(udld_options[0])
w = OptionMenu(top, udld_option_a, *udld_options)
w.grid(row=4, column=3)
Label(top, text="UDLD:", relief=RIDGE, width=22, fg='Blue').grid(row=4, column=6, sticky=E)
udld_option_b.set(udld_options[0])
w = OptionMenu(top, udld_option_b, *udld_options)
w.grid(row=4, column=7)

# LACP
Label(top, text="Link Aggregation Protocol:", relief=RIDGE, width=22, fg='Green').grid(row=5, column=0, sticky=E)
lacp_mode_a.set(lacp_modes[0])
w = OptionMenu(top, lacp_mode_a, *lacp_modes)
w.grid(row=5, column=1)
Label(top, text="Link Aggregation Protocol:", relief=RIDGE, width=22, fg='Blue').grid(row=5, column=4, sticky=E)
lacp_mode_b.set(lacp_modes[0])
w = OptionMenu(top, lacp_mode_b, *lacp_modes)
w.grid(row=5, column=5)

# Temp Links
Label(top, text="LB-Temp-link port:", relief=RIDGE, width=22, fg='Green').grid(row=5, column=2, sticky=E)
lb_temp_a.set(port_nums[0])
w = OptionMenu(top, lb_temp_a, *port_nums)
w.grid(row=5, column=3)
Label(top, text="LB-Temp-link port:", relief=RIDGE, width=22, fg='Blue').grid(row=5, column=6, sticky=E)
lb_temp_b.set(port_nums[0])
w = OptionMenu(top, lb_temp_b, *port_nums)
w.grid(row=5, column=7)
Label(top, text="Router Temp-link port:", relief=RIDGE, width=22, fg='Green').grid(row=6, column=0, sticky=E)
router_temp.set(port_nums[0])
w = OptionMenu(top, router_temp, *port_nums)
w.grid(row=6, column=1)

# Breakout Ports
Label(top, text="Breakout Ports: (eg. 31,32)", relief=RIDGE, width=22, fg='Blue').grid(row=6, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=breakout_ports).grid(row=6, column=5)

# UCS Domain Count
Label(top, text="No. of UCS Domains:", relief=RIDGE, width=22, fg='Blue').grid(row=6, column=6, sticky=E)
ucs_domain_count.set(ucs_domain_nums[0])
w = OptionMenu(top, ucs_domain_count, *ucs_domain_nums)
w.grid(row=6, column=7)


Label(top, text="############################################################# Common Details"
                " ###########################################################", font=('Times New Roman', 10, 'bold'))\
    .grid(row=7, column=1, sticky=E, columnspan=6)

# Domain Name
Label(top, text="Domain Name:", relief=RIDGE, width=22).grid(row=8, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=domain_name).grid(row=8, column=1)

# DNS
Label(top, text="DNS1,DNS2,...:", relief=RIDGE, width=22).grid(row=8, column=2, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=dns_ips).grid(row=8, column=3)

# NTP
Label(top, text="NTP1,NTP2,...:", relief=RIDGE, width=22).grid(row=8, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=ntp_ips).grid(row=8, column=5)

# Syslog Server
Label(top, text="Syslog/SNMP IP:", relief=RIDGE, width=22).grid(row=9, column=0, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=log_server).grid(row=9, column=1)

# Logging Level
Label(top, text="Logging Level:", relief=RIDGE, width=22).grid(row=9, column=2, sticky=E)
log_level.set(log_levels[7])
w = OptionMenu(top, log_level, *log_levels)
w.grid(row=9, column=3)

# Logging Facility
Label(top, text="Logging Facility:", relief=RIDGE, width=22).grid(row=9, column=4, sticky=E)
log_facility.set(log_facilities[4])
w = OptionMenu(top, log_facility, *log_facilities)
w.grid(row=9, column=5)

# SNMP Community
Label(top, text="SNMP Community:", relief=RIDGE, width=22).grid(row=9, column=6, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=25, textvariable=community).grid(row=9, column=7)

Label(top, text="################################################################ vLAN Details"
                " ###########################################################", font=('Times New Roman', 10, 'bold'))\
    .grid(row=10, column=1, sticky=E, columnspan=6)

# System vLAN Information
Label(top, text="System vLAN Info", relief=RIDGE, width=22, font=('Helvetica', 9, 'bold')).grid(row=11, column=0, sticky=E)
Label(top, text="vLAN Name", relief=RIDGE, width=22, font=('Helvetica', 9, 'bold')).grid(row=11, column=1, sticky=E)
Label(top, text="vLAN ID", relief=RIDGE, width=22, font=('Helvetica', 9, 'bold')).grid(row=11, column=2, sticky=E)
Label(top, text="vLAN Network (x.x.x.x/x)", relief=RIDGE, width=22, font=('Helvetica', 9, 'bold')).grid(row=11, column=3, sticky=E)
Label(top, text="Gateway", relief=RIDGE, width=22, font=('Helvetica', 9, 'bold')).grid(row=11, column=4, sticky=E)

# System MGMT vLAN
Label(top, text="System MGMT:", relief=RIDGE, width=22).grid(row=12, column=0, sticky=E)
oob_name = EntryWithPlaceholder(top, "vcesys-mgmt")
oob_name.grid(row=12, column=1)
oob_id = EntryWithPlaceholder(top, "101")
oob_id.grid(row=12, column=2)
oob_network = EntryWithPlaceholder(top, "192.168.101.0/24")
oob_network.grid(row=12, column=3)
oob_gateway = EntryWithPlaceholder(top, "192.168.101.1")
oob_gateway.grid(row=12, column=4)

# AMP Storage vLAN
Label(top, text="AMP Storage:", relief=RIDGE, width=22).grid(row=13, column=0, sticky=E)
storage_name = EntryWithPlaceholder(top, "vcesys-amp-iscsi")
storage_name.grid(row=13, column=1)
storage_id = EntryWithPlaceholder(top, "202")
storage_id.grid(row=13, column=2)

# ESXi MGMT vLAN
Label(top, text="ESXi MGMT:", relief=RIDGE, width=22).grid(row=14, column=0, sticky=E)
esx_name = EntryWithPlaceholder(top, "vcesys-esx-mgmt")
esx_name.grid(row=14, column=1)
esx_id = EntryWithPlaceholder(top, "105")
esx_id.grid(row=14, column=2)
esx_network = EntryWithPlaceholder(top, "192.168.105.0/24")
esx_network.grid(row=14, column=3)
esx_gateway = EntryWithPlaceholder(top, "192.168.105.1")
esx_gateway.grid(row=14, column=4)


# ESXi vMotion vLAN
Label(top, text="ESXi vMotion:", relief=RIDGE, width=22).grid(row=15, column=0, sticky=E)
esx_vm_name = EntryWithPlaceholder(top, "vcesys-esx-vmotion")
esx_vm_name.grid(row=15, column=1)
esx_vm_id = EntryWithPlaceholder(top, "106")
esx_vm_id.grid(row=15, column=2)


# ESXi FT vLAN
def activateEsxFt():
    if esx_ft_check.get() == 1:
        esx_ft_name.config(state=NORMAL)
        esx_ft_id.config(state=NORMAL)
    else:
        esx_ft_name.config(state=DISABLED)
        esx_ft_id.config(state=DISABLED)


Checkbutton(top, text="ESXi FT:", relief=RIDGE, width=19, padx=0.1, pady=0.1,
            variable=esx_ft_check, command=activateEsxFt).grid(row=16, column=0, sticky=E)
esx_ft_name = EntryWithPlaceholder(top, "vcesys-esx-ft")
esx_ft_name.grid(row=16, column=1)
esx_ft_id = EntryWithPlaceholder(top, "107")
esx_ft_id.grid(row=16, column=2)
esx_ft_name.config(state=DISABLED)
esx_ft_id.config(state=DISABLED)

# ESXi Build vLAN
Label(top, text="ESXi Build:", relief=RIDGE, width=22).grid(row=17, column=0, sticky=E)
build_name = EntryWithPlaceholder(top, "vcesys-esx-build")
build_name.grid(row=17, column=1)
build_id = EntryWithPlaceholder(top, "110")
build_id.grid(row=17, column=2)


# vCenter HA vLAN
def activateVcHa():
    if vc_ha_check.get() == 1:
        vc_ha_name.config(state=NORMAL)
        vc_ha_id.config(state=NORMAL)
    else:
        vc_ha_name.config(state=DISABLED)
        vc_ha_id.config(state=DISABLED)


Checkbutton(top, text="vCenter HA:", relief=RIDGE, width=19, padx=0.1, pady=0.1,
            variable=vc_ha_check, command=activateVcHa).grid(row=18, column=0, sticky=E)
vc_ha_name = EntryWithPlaceholder(top, "vcenter_ha")
vc_ha_name.grid(row=18, column=1)
vc_ha_id = EntryWithPlaceholder(top, "203")
vc_ha_id.grid(row=18, column=2)
vc_ha_name.config(state=DISABLED)
vc_ha_id.config(state=DISABLED)

# AMP MGMT vLAN
Label(top, text="In-Band MGMT:", relief=RIDGE, width=22).grid(row=19, column=0, sticky=E)
amp_name = EntryWithPlaceholder(top, "amp_esx_mgmt")
amp_name.grid(row=19, column=1)
amp_id = EntryWithPlaceholder(top, "205")
amp_id.grid(row=19, column=2)
amp_network = EntryWithPlaceholder(top, "192.168.205.0/24")
amp_network.grid(row=19, column=3)
amp_gateway = EntryWithPlaceholder(top, "192.168.205.1")
amp_gateway.grid(row=19, column=4)


# AMP vMotion vLAN
Label(top, text="vMotion-AMP:", relief=RIDGE, width=22).grid(row=20, column=0, sticky=E)
amp_vm_name = EntryWithPlaceholder(top, "amx_esx_vmotion")
amp_vm_name.grid(row=20, column=1)
amp_vm_id = EntryWithPlaceholder(top, "206")
amp_vm_id.grid(row=20, column=2)
amp_vm_network = EntryWithPlaceholder(top, "192.168.206.0/24")
amp_vm_network.grid(row=20, column=3)
amp_vm_gateway = EntryWithPlaceholder(top, "192.168.206.1")
amp_vm_gateway.grid(row=20, column=4)


# AMP FT vLAN
def activateAmpFt():
    if amp_ft_check.get() == 1:
        amp_ft_name.config(state=NORMAL)
        amp_ft_id.config(state=NORMAL)
    else:
        amp_ft_name.config(state=DISABLED)
        amp_ft_id.config(state=DISABLED)


Checkbutton(top, text="AMP FT:", relief=RIDGE, width=19, padx=0.1, pady=0.1,
            variable=amp_ft_check, command=activateAmpFt).grid(row=21, column=0, sticky=E)
amp_ft_name = EntryWithPlaceholder(top, "amx_esx_ft")
amp_ft_name.grid(row=21, column=1)
amp_ft_id = EntryWithPlaceholder(top, "207")
amp_ft_id.grid(row=21, column=2)
amp_ft_name.config(state=DISABLED)
amp_ft_id.config(state=DISABLED)

# Unused Port vLAN
Label(top, text="Unused Port Security:", relief=RIDGE, width=22).grid(row=22, column=0, sticky=E)
unused_name = EntryWithPlaceholder(top, "unused_port_security")
unused_name.grid(row=22, column=1)
unused_id = EntryWithPlaceholder(top, "911")
unused_id.grid(row=22, column=2)

Label(top, text="##################################################### Customer and Unified vLAN Details"
                " ####################################################", font=('Times New Roman', 10, 'bold'))\
    .grid(row=23, column=1, sticky=E, columnspan=6)
# Customer vLAN
Label(top, text="Customer vLANs:", relief=RIDGE, width=22).grid(row=24, column=0, sticky=E)
Label(top, text="Name1,Name2,...:", relief=RIDGE, width=22).grid(row=24, column=1, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=customer_names).grid(row=24, column=2, columnspan=2)
Label(top, text="ID1,ID2,...:", relief=RIDGE, width=22).grid(row=24, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=customer_ids).grid(row=24, column=5, columnspan=2)

# Unified internal vLAN
Label(top, text="Unified Internal vLANs: ", relief=RIDGE, width=22).grid(row=25, column=0, sticky=E)
Label(top, text="Name1,Name2,...:", relief=RIDGE, width=22).grid(row=25, column=1, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=unified_in_names).grid(row=25, column=2, columnspan=2)
Label(top, text="ID1,ID2,...:", relief=RIDGE, width=22).grid(row=25, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=unified_in_ids).grid(row=25, column=5, columnspan=2)

# Unified external vLAN
Label(top, text="Unified External vLANs: ", relief=RIDGE, width=22).grid(row=26, column=0, sticky=E)
Label(top, text="Name1,Name2,...:", relief=RIDGE, width=22).grid(row=26, column=1, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=unified_ex_names).grid(row=26, column=2, columnspan=2)
Label(top, text="ID1,ID2,...:", relief=RIDGE, width=22).grid(row=26, column=4, sticky=E)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=unified_ex_ids).grid(row=26, column=5, columnspan=2)

# Port-Map Upload
Label(top, text="Port-Map:", relief=RIDGE, width=22).grid(row=27, column=0, sticky=E)


def browsefunc():
    filename = filedialog.askopenfilename(filetypes=(("Excel files", "*.xlsx"), ("All files", "*.*")))
    port_map_location.set(filename)


btn1 = Button(top, text='Browse', bg='brown', fg='white', command=browsefunc).grid(row=27, column=3, sticky=W)
Entry(top, bg='white', relief=SUNKEN, width=50, textvariable=port_map_location).grid(row=27, column=1, columnspan=2)

btn2 = Button(top, text='Generate Scripts', bg='brown', fg='white', command=submit).grid(row=28, column=7, columnspan=2)

top.mainloop()
