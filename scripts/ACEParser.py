from pyparsing import Optional, Word, nums, oneOf, Keyword, Or, OneOrMore, ZeroOrMore, StringEnd
from enum import Enum
# import logging
# import device_util as device_util
#
# logging.getLogger('ACEParser')
# logging.basicConfig(format='[%(asctime)s %(filename)s] %(message)s', level=logging.INFO)


class L4SrcDst(Enum):
    SRC = 1
    DST = 2

#
# ACE Grammar
#


# sequence number, optiuonal at start of ACE
seq_no = Optional(Word(nums)('seq'))

# action, either permit or deny
action = oneOf('permit deny')('action')

# log
log = Or([
    Keyword('log'),
    Keyword('log-input')])('log-action')


# tcp flags
tcp_flags_set_notset = oneOf([
    '+ack',
    '+fin',
    '+psh',
    '+rst',
    '+syn',
    '+urg',
    '-ack',
    '-fin',
    '-psh',
    '-rst',
    '-syn',
    '-urg',
])
tcp_flags_match_any = Keyword('match-any') + OneOrMore(tcp_flags_set_notset)
tcp_flags_match_all = Keyword('match-all') + OneOrMore(tcp_flags_set_notset)
tcp_flags_simple = oneOf([
    'established',
    'ack',
    'fin',
    'psh',
    'rst',
    'syn',
    'urg'])
tcp_flags = OneOrMore(
    tcp_flags_simple |
    tcp_flags_match_all |
    tcp_flags_match_any)('tcp_flag')


# dscp
dscp_codepoints = [
    'af11',
    'af12',
    'af13',
    'af21',
    'af22',
    'af23',
    'af31',
    'af32',
    'af33',
    'af41',
    'af42',
    'af43',
    'cs1',
    'cs2',
    'cs3',
    'cs4',
    'cs5',
    'cs6',
    'cs7',
    'default',
    'ef',
]
dscp = Keyword('dscp') + Or([oneOf(dscp_codepoints), Word(nums)('dscp_codepoint')])


# precedence
precedence_values = [
    'critical',
    'flash',
    'flash-overridence',
    'immediate',
    'internet',
    'network',
    'priority',
    'routine',
]
precedence = Keyword('precedence') + Or([Word(nums), oneOf(precedence_values)])


# fragments
fragments = Keyword('fragments')


# ip options
ip_options = [
    'add-ext',
    'any-options',
    'com-security',
    'dps',
    'encode',
    'eool',
    'ext-ip',
    'ext-security',
    'finn',
    'imitd',
    'lsr',
    'mtup',
    'mtur',
    'no-op',
    'nsapa',
    'record-router',
    'router-alert',
    'sdb',
    'security',
    'ssr',
    'stream-id',
    'timestamp',
    'traceroute',
    'ump',
    'visa',
    'zsu',
]
ip_option = Keyword('option') + Or([oneOf(ip_options), Word(nums)])


# tos
tos_values = [
    'max-reliability',
    'max-throughput',
    'min-delay',
    'min-monetary-cost',
    'normal',
]
tos = Keyword('tos') + Or([oneOf(tos_values), Word(nums)])


# ttl
ttl_oper = [
    'eq',
    'neq',
    'lt',
    'gt',
]
ttl_single = oneOf(ttl_oper) + Word(nums)
ttl_range = Keyword('range') + Word(nums) + Word(nums)
ttl_specifier = Or([ttl_single, ttl_range])
ttl = Keyword('ttl') + ttl_specifier


# pool of "other"
OTHER = dscp | fragments | log | ip_option | precedence | tos | ttl


# icmp
icmp_messages = [
    'administratively-prohibited',
    'alternate-address',
    'conversion-error',
    'dod-host-prohibited',
    'dod-net-prohibited',
    'echo',
    'echo-reply',
    'general-parameter-problem',
    'host-isolated',
    'host-precedence-unreachable',
    'host-redirect',
    'host-tos-redirect',
    'host-tos-unreachable',
    'host-unknown',
    'host-unreachable',
    'information-reply',
    'information-request',
    'mask-reply',
    'mask-request',
    'mobile-redirect',
    'net-redirect',
    'net-tos-redirect',
    'net-tos-unreachable',
    'net-unreachable',
    'network-unknown',
    'no-room-for-option',
    'option-missing',
    'packet-too-big',
    'parameter-problem',
    'port-unreachable',
    'precedence-unreachable',
    'protocol-unreachable',
    'reassembly-timeout',
    'redirect',
    'router-advertisement',
    'router-solicitation',
    'source-quench',
    'source-route-failed',
    'time-exceeded',
    'timestamp-reply',
    'timestamp-request',
    'traceroute',
    'ttl-exceeded',
    'unreachable',
]
icmp_message = oneOf(icmp_messages)('icmp_message')


# igmp options
igmp_options = [
    'dvmrp',
    'host-query',
    'host-repor',
    'pim',
    'trace',
]
igmp_option = oneOf(igmp_options)

#
# TCP named ports
#
tcp_bgp = (Keyword('bgp') | Keyword('179'))('tcpport')
tcp_chargen = (Keyword('chargen') | Keyword('19'))('tcpport')
tcp_cmd = (Keyword('cmd') | Keyword('514'))('tcpport')
tcp_daytime = (Keyword('daytime') | Keyword('13'))('tcpport')
tcp_discard = (Keyword('discard') | Keyword('9'))('tcpport')
tcp_domain = (Keyword('domain') | Keyword('53'))('tcpport')
tcp_echo = (Keyword('echo') | Keyword('7'))('tcpport')
tcp_exec = (Keyword('exec') | Keyword('512'))('tcpport')
tcp_finger = (Keyword('finger') | Keyword('79'))('tcpport')
tcp_ftp = (Keyword('ftp') | Keyword('21'))('tcpport')
tcp_ftp_data = (Keyword('ftp-data') | Keyword('20'))('tcpport')
tcp_gopher = (Keyword('gopher') | Keyword('70'))('tcpport')
tcp_hostname = (Keyword('hostname') | Keyword('101'))('tcpport')
tcp_ident = (Keyword('ident') | Keyword('113'))('tcpport')
tcp_irc = (Keyword('irc') | Keyword('194'))('tcpport')
tcp_klogin = (Keyword('klogin') | Keyword('543'))('tcpport')
tcp_kshell = (Keyword('kshell') | Keyword('544Kerberos shell (544)'))('tcpport')
tcp_login = (Keyword('login') | Keyword('513'))('tcpport')
tcp_lpd = (Keyword('lpd') | Keyword('515'))('tcpport')
tcp_msrpc = (Keyword('msrpc') | Keyword('135'))('tcpport')
tcp_nntp = (Keyword('nntp') | Keyword('119'))('tcpport')
tcp_onep_plain = (Keyword('onep-plain') | Keyword('15001'))('tcpport')
tcp_onep_tls = (Keyword('onep-tls') | Keyword('15002'))('tcpport')
tcp_pim_auto_rp = (Keyword('pim-auto-rp') | Keyword('496'))('tcpport')
tcp_pop2 = (Keyword('pop2') | Keyword('109'))('tcpport')
tcp_pop3 = (Keyword('pop3') | Keyword('110'))('tcpport')
tcp_smtp = (Keyword('smtp') | Keyword('25'))('tcpport')
tcp_sunrpc = (Keyword('sunrpc') | Keyword('111'))('tcpport')
tcp_syslog = (Keyword('syslog') | Keyword('514'))('tcpport')
tcp_tacacs = (Keyword('tacacs') | Keyword('49'))('tcpport')
tcp_talk = (Keyword('talk') | Keyword('517'))('tcpport')
tcp_telnet = (Keyword('telnet') | Keyword('23'))('tcpport')
tcp_time = (Keyword('time') | Keyword('23'))('tcpport')
tcp_uucp = (Keyword('uucp') | Keyword('540'))('tcpport')
tcp_whois = (Keyword('whois') | Keyword('43'))('tcpport')
tcp_www = (Keyword('www') | Keyword('80'))('tcpport')

tcp_ports = (
    tcp_bgp | tcp_chargen | tcp_cmd | tcp_daytime |
    tcp_discard | tcp_domain | tcp_echo | tcp_exec | tcp_finger |
    tcp_ftp | tcp_ftp_data | tcp_gopher | tcp_hostname | tcp_ident |
    tcp_irc | tcp_klogin | tcp_kshell | tcp_login | tcp_lpd |
    tcp_msrpc | tcp_nntp | tcp_onep_plain | tcp_onep_tls |
    tcp_pim_auto_rp | tcp_pop2 | tcp_pop3 | tcp_smtp | tcp_sunrpc |
    tcp_syslog | tcp_tacacs | tcp_talk | tcp_telnet | tcp_time |
    tcp_uucp | tcp_whois | tcp_www | Word(nums)
)

tcp_port_name_to_int = {
    'bgp': '179', 'chargen': '19', 'cmd': '514',
    'daytime': '13', 'discard': '9', 'domain': '53', 'echo': '7',
    'exec': '512', 'finger': '79', 'ftp': '21', 'ftp-data': '20',
    'gopher': '70', 'hostname': '101', 'ident': '113', 'irc': '194',
    'klogin': '543', 'kshell': '544', 'login': '513', 'lpd': '515',
    'msrpc': '135', 'nntp': '119', 'onep-plain': '15001', 'onep-tls':
    '15002', 'pim-auto-rp': '496', 'pop2': '109', 'pop3': '110',
    'smtp': '25', 'sunrpc': '111', 'syslog': '514', 'tacacs': '49',
    'talk': '517', 'telnet': '23', 'time': '23', 'uucp': '540',
    'whois': '43', 'www': '80',
}


#
# UDP named ports
#
udp_biff = (Keyword('biff') | Keyword('512'))('udpport')
udp_bootpc = (Keyword('bootpc') | Keyword('68'))('udpport')
udp_bootps = (Keyword('bootps') | Keyword('67'))('udpport')
udp_discard = (Keyword('discard') | Keyword('9'))('udpport')
udp_dnsix = (Keyword('dnsix') | Keyword('195'))('udpport')
udp_domain = (Keyword('domain') | Keyword('53'))('udpport')
udp_echo = (Keyword('echo') | Keyword('7'))('udpport')
udp_isakmp = (Keyword('isakmp') | Keyword('500'))('udpport')
udp_mobile_ip = (Keyword('mobile-ip') | Keyword('434'))('udpport')
udp_nameserver = (Keyword('nameserver') | Keyword('42'))('udpport')
udp_netbios_dgm = (Keyword('netbios-dgm') | Keyword('138'))('udpport')
udp_netbios_ns = (Keyword('netbios-ns') | Keyword('137'))('udpport')
udp_netbios_ss = (Keyword('netbios-ss') | Keyword('139'))('udpport')
udp_non500_isakmp = (Keyword('non500-isakmp') | Keyword('4500'))('udpport')
udp_ntp = (Keyword('ntp') | Keyword('123'))('udpport')
udp_pim_auto_rp = (Keyword('pim-auto-rp') | Keyword('496'))('udpport')
udp_rip = (Keyword('rip') | Keyword('520'))('udpport')
udp_ripv6 = (Keyword('ripv6') | Keyword('521'))('udpport')
udp_snmp = (Keyword('snmp') | Keyword('161'))('udpport')
udp_snmptrap = (Keyword('snmptrap') | Keyword('162'))('udpport')
udp_sunrpc = (Keyword('sunrpc') | Keyword('111'))('udpport')
udp_syslog = (Keyword('syslog') | Keyword('514'))('udpport')
udp_tacacs = (Keyword('tacacs') | Keyword('49'))('udpport')
udp_talk = (Keyword('talk') | Keyword('517'))('udpport')
udp_tftp = (Keyword('tftp') | Keyword('69'))('udpport')
udp_time = (Keyword('time') | Keyword('37'))('udpport')
udp_who = (Keyword('who') | Keyword('513'))('udpport')
udp_xdmcp = (Keyword('xdmcp') | Keyword('177'))('udpport')

udp_ports = (
    udp_biff | udp_bootpc | udp_bootps | udp_discard |
    udp_dnsix | udp_domain | udp_echo | udp_isakmp | udp_mobile_ip |
    udp_nameserver | udp_netbios_dgm | udp_netbios_ns | udp_netbios_ss
    | udp_non500_isakmp | udp_ntp | udp_pim_auto_rp | udp_rip |
    udp_ripv6 | udp_snmp | udp_snmptrap | udp_sunrpc | udp_syslog |
    udp_tacacs | udp_talk | udp_tftp | udp_time | udp_who | udp_xdmcp
    | Word(nums)
)

udp_port_name_to_int = {
    'biff': '512', 'bootpc': '68', 'bootps':
    '67', 'discard': '9', 'dnsix': '195', 'domain': '53', 'echo': '7',
    'isakmp': '500', 'mobile-ip': '434', 'nameserver': '42',
    'netbios-dgm': '138', 'netbios-ns': '137', 'netbios-ss': '139',
    'non500-isakmp': '4500', 'ntp': '123', 'pim-auto-rp': '496',
    'rip': '520', 'ripv6': '521', 'snmp': '161', 'snmptrap': '162',
    'sunrpc': '111', 'syslog': '514', 'tacacs': '49', 'talk': '517',
    'tftp': '69', 'time': '37', 'who': '513', 'xdmcp': '177',
}


# the TCP "src" clause
l4_tcp_src_port_single_operator = oneOf('eq neq lt gt')('src_oper') + tcp_ports('src_port')
l4_tcp_src_port_range_operator = Keyword('range')('src_oper') + tcp_ports('src_port_lower') + tcp_ports('src_port_upper')
l4_tcp_src_port_specifier = Or([
    l4_tcp_src_port_single_operator,
    l4_tcp_src_port_range_operator])
l4_tcp_src = Keyword('src') + l4_tcp_src_port_specifier


# the TCP "dst" clause
l4_tcp_dst_port_single_operator = oneOf('eq neq lt gt')('dst_oper') + tcp_ports('dst_port')
l4_tcp_dst_port_range_operator = Keyword('range')('dst_oper') + tcp_ports('dst_port_lower') + tcp_ports('dst_port_upper')
l4_tcp_dst_port_specifier = Or([
    l4_tcp_dst_port_single_operator,
    l4_tcp_dst_port_range_operator])
l4_tcp_dst = Keyword('dst') + l4_tcp_dst_port_specifier


# top level l4 TCP starting point
l4_tcp = (Optional(l4_tcp_src)('l4_src') + Optional(l4_tcp_dst)('l4_dst'))


# the UDP "src" clause
l4_udp_src_port_single_operator = oneOf('eq neq lt gt')('src_oper') + udp_ports('src_port')
l4_udp_src_port_range_operator = Keyword('range')('src_oper') + udp_ports('src_port_lower') + udp_ports('src_port_upper')
l4_udp_src_port_specifier = Or([
    l4_udp_src_port_single_operator,
    l4_udp_src_port_range_operator])
l4_udp_src = Keyword('src') + l4_udp_src_port_specifier


# the UDP "dst"
l4_udp_dst_port_single_operator = oneOf('eq neq lt gt')('dst_oper') + udp_ports('dst_port')
l4_udp_dst_port_range_operator = Keyword('range')('dst_oper') + udp_ports('dst_port_lower') + udp_ports('dst_port_upper')
l4_udp_dst_port_specifier = Or([
    l4_udp_dst_port_single_operator,
    l4_udp_dst_port_range_operator])
l4_udp_dst = Keyword('dst') + l4_udp_dst_port_specifier


# top level l4 UDP starting point
l4_udp = (Optional(l4_udp_src)('l4_src') + Optional(l4_udp_dst)('l4_dst'))


# base protocols
icmp = (Keyword('icmp') | Keyword('1'))('protocol')
igmp = (Keyword('igmp') | Keyword('2'))('protocol')
tcp = (Keyword('tcp') | Keyword('6'))('protocol')
udp = (Keyword('udp') | Keyword('17'))('protocol')
gre = (Keyword('gre') | Keyword('47'))('protocol')
esp = (Keyword('esp') | Keyword('50'))('protocol')
ahp = (Keyword('ahp') | Keyword('51'))('protocol')
eigrp = (Keyword('eigrp') | Keyword('88'))('protocol')
ospf = (Keyword('ospf') | Keyword('89'))('protocol')
ipinip = (Keyword('ipinip') | Keyword('94'))('protocol')
pim = (Keyword('pim') | Keyword('103'))('protocol')
ip = Keyword('ip')('protocol')
nos = Keyword('nos')('protocol')
pcp = Keyword('pcp')('protocol')


# build up the various individual protocols; note that these will actually
# accept overall more insatances of things than will appear in an ACE; for
# example, "deny tcp dscp ef dscp af11" would be accepted
protocol_icmp = icmp + ZeroOrMore(icmp_message | OTHER)
protocol_tcp = tcp + Optional(l4_tcp) + ZeroOrMore(tcp_flags | OTHER)
protocol_udp = udp + Optional(l4_udp) + ZeroOrMore(OTHER)
protocol_igmp = igmp + ZeroOrMore(igmp_option | OTHER)
protocol_named = (ahp | eigrp | esp | gre | ip | ipinip | nos | ospf | pcp | pim) + ZeroOrMore(OTHER)
protocol_numbered = Word(nums)('protocol') + ZeroOrMore(OTHER)


# OR them all together
protocol = (
    protocol_tcp |
    protocol_udp |
    protocol_icmp |
    protocol_igmp |
    protocol_named |
    protocol_numbered) + StringEnd()

#
# putting it all together!
#
ace_parser = seq_no + action + protocol


#
# display l4 ACE parameters; this is a little clumsy
#
# def display_l4_criteria(r, srcOrDest:L4SrcDst, aces_seen):
#     t = None
#     if srcOrDest == L4SrcDst.SRC:
#         if 'l4_src' in r:
#             logging.debug('l4_src {}'.format(r['l4_src']))
#             if 'src_oper' in r:
#                 logging.debug('src_oper {}'.format(r['src_oper']))
#             if 'src_port' in r:
#                 logging.debug('src_port {}'.format(r['src_port']))
#                 port_no = r['src_port']
#                 if (r['protocol'] == '17' or r['protocol'] == 'udp') and \
#                         r['src_port'] in udp_port_name_to_int.keys():
#                     port_no = udp_port_name_to_int[r['src_port']]
#                 elif (r['protocol'] == '6' or r['protocol'] == 'tcp') and \
#                         r['src_port'] in tcp_port_name_to_int.keys():
#                     port_no = tcp_port_name_to_int[r['src_port']]
#                 count = device_util.get_port_count(r['src_oper'], port_no)
#                 key = 'src' + ' ' + r['src_oper']
#                 if key in aces_seen.keys():
#                     if r['src_oper'] == 'gt' or r['src_oper'] == 'lt':
#                         aces_seen[key] = max(aces_seen[key], count)
#                     else:
#                         aces_seen[key] += 1
#                 else:
#                     aces_seen[key] = count
#             if 'src_port_lower' in r:
#                 logging.debug('src_port_lower {}'.format(r['src_port_lower']))
#             if 'src_port_upper' in r:
#                 logging.debug('src_port_upper {}'.format(r['src_port_upper']))
#     elif srcOrDest == L4SrcDst.DST:
#         if 'l4_dst' in r:
#             logging.debug('l4_dst {}'.format(r['l4_dst']))
#             if 'dst_oper' in r:
#                 logging.debug('dst_oper {}'.format(r['dst_oper']))
#             if 'dst_port' in r:
#                 logging.debug('dst_port {}'.format(r['dst_port']))
#                 port_no = r['dst_port']
#                 if (r['protocol'] == '17' or r['protocol'] == 'udp') and \
#                         r['dst_port'] in udp_port_name_to_int.keys():
#                     port_no = udp_port_name_to_int[r['dst_port']]
#                 elif (r['protocol'] == '6' or r['protocol'] == 'tcp') and \
#                         r['dst_port'] in tcp_port_name_to_int.keys():
#                     port_no = tcp_port_name_to_int[r['src_port']]
#                 count = device_util.get_port_count(r['dst_oper'], port_no)
#                 key = 'dst' + ' ' + r['dst_oper']
#                 if key in aces_seen.keys():
#                     if r['dst_oper'] == 'gt' or r['dst_oper'] == 'lt':
#                         aces_seen[key] = max(aces_seen[key], count)
#                     else:
#                         aces_seen[key] += 1
#                 else:
#                     aces_seen[key] = count
#             if 'dst_port_lower' in r:
#                 logging.debug('dst_port_lower {}'.format(r['dst_port_lower']))
#             if 'dst_port_upper' in r:
#                 logging.debug('dst_port_upper {}'.format(r['dst_port_upper']))
#     else:
#         raise Exception('incorrect type')
#
#
# working_ace1 = [
#     '12 permit 6 dst eq 1 ',
#     '13 permit 6 src eq 2 ',
# ]
#
# working_ace2 = [
#     '12 permit 17 src gt 10',
#     '13 permit 17 src gt 100',
#     '14 permit 17 src gt 500',
# ]
#
# working_ace3 = [
#     '10 permit tcp src range 1 10 match-all -ack syn',
# ]
#
# working_ace4 = [
#     '12 permit 17 src gt 10',
#     '13 permit 17 src lt 100',
#     '14 permit 17 src gt 500',
# ]
#
# working_ace5 = [
#     '12 permit 17 src gt 10',
#     '13 permit 17 src gt 100',
#     '14 permit 17 src gt 500',
#     '15 deny 17 src gt 10'
# ]
#
# working_ace6 = [
#     '12 permit 17 src gt 10',
#     '13 permit 6 dst gt 100',
#     '14 permit 17 src gt 500',
#     '15 deny 17 src gt 10'
# ]
#
#
# not_working_ace1 = [
#     '11 permit 6 src gt 10 dst gt 10',
#     '12 permit 6 src gt 10'
# ]
#
# # range condition todo
# not_working_ace2 = [
#     '11 permit 6 src range 1 10',
# ]
#
# # neq condition
# working_ace7 = [
#     '11 permit 6 src neq 10',
# ]
#
# not_working_ace4 = [
#     '10 permit tcp ack psh syn dscp af11 option any-options log'
# ]
#
# #
# # let's do some testing
# #
# if __name__ == '__main__':
#
#     print("utilization: ", device_util.get_utilization(working_ace1))
#     print("utilization: ", device_util.get_utilization(working_ace2))
#     print("utilization: ", device_util.get_utilization(working_ace3))
#     print("utilization: ", device_util.get_utilization(working_ace4))
#     print("utilization: ", device_util.get_utilization(working_ace5))
#     print("utilization: ", device_util.get_utilization(working_ace6))
#     print("utilization: ", device_util.get_utilization(working_ace7))
#
#     print("utilization: ", device_util.get_utilization(not_working_ace1))
#     print("utilization: ", device_util.get_utilization(not_working_ace2))
#     print("utilization: ", device_util.get_utilization(not_working_ace4))

if __name__ == '__main__':
    # r = ace_parser.parseString("permit tcp src eq 3370 dst range 3389 3390")
    r = ace_parser.parseString("permit tcp src eq 3370")
    print(r.asDict())
