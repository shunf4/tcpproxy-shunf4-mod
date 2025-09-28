#!/usr/bin/env  python3
import argparse
import pkgutil
import os
import sys
import threading
import socket
import socks
import ssl
import time
import select
import errno
import ipaddress
import datetime
import tempfile
import contextlib
import traceback

import socks5

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

if '' not in sys.path:
    sys.path.insert(0, '')

# TODO: implement verbose output
# some code snippets, as well as the original idea, from Black Hat Python


def is_valid_ip4(ip):
    # some rudimentary checks if ip is actually a valid IP
    octets = ip.split('.')
    if len(octets) != 4:
        return False

    try:
        return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False


def parse_args():
    parser = argparse.ArgumentParser(description='Simple TCP proxy for data ' +
                                                 'interception and ' +
                                                 'modification. ' +
                                                 'Select modules to handle ' +
                                                 'the intercepted traffic.')

    parser.add_argument('-ti', '--targetip', dest='target_ip',
                        help='remote target IP or host name. not effective when using SOCKS5 mode.')

    parser.add_argument('-tp', '--targetport', dest='target_port', type=int,
                        help='remote target port. not effective when using SOCKS5 mode.')

    parser.add_argument('-li', '--listenip', dest='listen_ip',
                        default='0.0.0.0', help='IP address/host name to listen for ' +
                        'incoming data (or SOCKS5 client connection)')

    parser.add_argument('-lp', '--listenport', dest='listen_port', type=int,
                        default=8080, help='port to listen on for incoming data (or SOCKS5 client connection)')

    parser.add_argument('-s5', '--socks5', dest='use_socks5', default=False,
                        action='store_true',
                        help='enable SOCKS5 mode (acts as a SOCKS5 server and intercept proxy connections)')

    parser.add_argument('-pi', '--proxy-ip', dest='proxy_ip', default=None,
                        help='IP address/host name of proxy')

    parser.add_argument('-pp', '--proxy-port', dest='proxy_port', type=int,
                        default=1080, help='proxy port', )

    parser.add_argument('-pt', '--proxy-type', dest='proxy_type', default='SOCKS5', choices=['SOCKS4', 'SOCKS5', 'HTTP'],
                        type = str.upper, help='proxy type. Options are SOCKS5 (default), SOCKS4, HTTP')

    parser.add_argument('-om', '--outmodules', dest='out_modules',
                        help='comma-separated list of modules to modify data' +
                             ' before sending to remote target.')

    parser.add_argument('-im', '--inmodules', dest='in_modules',
                        help='comma-separated list of modules to modify data' +
                             ' received from the remote target.')

    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
                        action='store_true',
                        help='More verbose output of status information')

    parser.add_argument('-n', '--no-chain', dest='no_chain_modules',
                        action='store_true', default=False,
                        help='Don\'t send output from one module to the ' +
                             'next one')

    parser.add_argument('-l', '--log', dest='logfile', default=None,
                        help='Log all data to a file before modules are run.')

    parser.add_argument('--list', dest='list', action='store_true',
                        help='list available modules')

    parser.add_argument('-lo', '--list-options', dest='help_modules', default=None,
                        help='Print help of selected module')

    parser.add_argument('-s', '--ssl', dest='use_ssl', action='store_true',
                        default=False, help='detect SSL/TLS as well as STARTTLS')

    parser.add_argument('-ac', '--ca-certificate', default='mitm.pem',
                        help='ca certificate (for signing server certificate) in PEM format (default: %(default)s)')

    parser.add_argument('-ak', '--ca-key', default='mitm.pem',
                        help='ca certificate (for signing server certificate) key in PEM format (default: %(default)s)')

    parser.add_argument('-cc', '--client-certificate', default=None,
                        help='client certificate in PEM format in case client authentication is required by the target')

    parser.add_argument('-ck', '--client-key', default=None,
                        help='client key in PEM format in case client authentication is required by the target')

    return parser.parse_args()


def generate_module_list(modstring, incoming=False, verbose=False):
    # This method receives the comma-separated module list, imports the modules
    # and creates a Module instance for each module. A list of these instances
    # is then returned.
    # The incoming parameter is True when the modules belong to the incoming
    # chain (-im)
    # modstring looks like mod1,mod2:key=val,mod3:key=val:key2=val2,mod4 ...
    modlist = []
    namelist = modstring.split(',')
    for n in namelist:
        name, options = parse_module_options(n)
        try:
            __import__('proxymodules.' + name)
            modlist.append(sys.modules['proxymodules.' + name].Module(incoming, verbose, options))
        except ImportError:
            print('Module %s not found' % name)
            sys.exit(3)
    return modlist


def parse_module_options(n):
    # n is of the form module_name:key1=val1:key2=val2 ...
    # this method returns the module name and a dict with the options
    n = n.split(':', 1)
    if len(n) == 1:
        # no module options present
        return n[0], None
    name = n[0]
    optionlist = n[1].split(':')
    options = {}
    i = 0
    while i < len(optionlist):
        op = optionlist[i]
        try:
            k, v = op.split('=')
            if len(v) > 1 and v[0] == '"' and v[-1] != '"':
                while True:
                    i += 1
                    op = optionlist[i]
                    v += ":"
                    v += op
                    if len(op) > 0 and op[-1] == '"':
                        break
                v = v[1:-1]
            elif len(v) > 1 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            options[k] = v
            i += 1
        except ValueError:
            print(op, ' is not valid!')
            sys.exit(23)
    return name, options


def list_modules():
    # show all available proxy modules
    cwd = os.getcwd()
    module_path = cwd + os.sep + 'proxymodules'
    for _, module, _ in pkgutil.iter_modules([module_path]):
        __import__('proxymodules.' + module)
        m = sys.modules['proxymodules.' + module].Module()
        print(f'{m.name} - {m.description}')


def print_module_help(modlist):
    # parse comma-separated list of module names, print module help text
    modules = generate_module_list(modlist)
    for m in modules:
        try:
            print(f'{m.name} - {m.description}')
            print(m.help())
        except AttributeError:
            print('\tNo options or missing help() function.')


def update_module_hosts(modules, source, destination, remote_hostname, timestamp):
    # set source and destination IP/port for each module
    # source and destination are ('IP', port) tuples
    # this can only be done once local and remote connections have been established
    if modules is not None:
        for m in modules:
            if hasattr(m, 'source'):
                m.source = source
            if hasattr(m, 'destination'):
                m.destination = destination

            create_context = getattr(m, 'create_context', None)
            if callable(create_context):
                ctx = create_context(timestamp)
                ctx.update({
                    'source': source,
                    'destination': destination,
                    'remote_hostname': remote_hostname,
                    'timestamp': timestamp,
                })


def receive_from(s):
    # receive data from a socket until no more data is there
    # returns error if SSLWantReadError is raised
    b = bytearray(b"")
    while len(b) < 81920:
        try:
            data = s.recv(4096)
        except Exception as e:
            return b, e
        b += data
        if not data or len(data) < 4096:
            break
    return b, None

def send_to(s, data, peer, args):
    # write data to a socket until no more data is about to be sent
    # retry if SSLWantWriteError is raised
    if hasattr(s, '_sslobj') and s._sslobj is not None:
        count = 0
        with memoryview(data) as view, view.cast("B") as byte_view:
            amount = len(byte_view)
            want_write = False
            while count < amount:
                if want_write:
                    time.sleep(0.1)
                    want_write = False
                    continue
                else:
                    pass

                try:
                    v = s.send(byte_view[count:])
                except ssl.SSLWantWriteError as e:
                    vprint("SSLWantWriteError, with %s:%d" % peer, args.verbose)
                    log(args.logfile, "SSLWantWriteError, with %s:%d" % peer)
                    want_write = True
                    continue
                count += v
    else:
        return s.sendall(data)

def handle_data(data, timestamp, modules, dont_chain, incoming, verbose):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        vprint(("> > > > in: " if incoming else "< < < < out: ") + m.name, verbose)
        execute_ex = getattr(m, "execute_ex", None)
        if execute_ex:
            if dont_chain:
                execute_ex(data, timestamp)
            else:
                data = execute_ex(data, timestamp)
        else:
            if dont_chain:
                m.execute(data)
            else:
                data = m.execute(data)
    return data

def handle_close(timestamp, modules, incoming, verbose):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        vprint(("> > > > close" if incoming else "< < < < close") + m.name, verbose)
        mhandle_close = getattr(m, "mhandle_close", None)
        if mhandle_close:
            mhandle_close(timestamp)
        elif hasattr(m, 'mhandle_close') and m.mhandle_close is not None:
            m.mhandle_close(timestamp)


def is_client_hello(sock):
    firstbytes = sock.recv(128, socket.MSG_PEEK)
    return (len(firstbytes) >= 3 and
            firstbytes[0] == 0x16 and
            firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
            )
            
def try_into_ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None

def create_host_cert(args, host):
    vprint('Generating host certificate for %s' % host, args.verbose)
    log(args.logfile, 'Generating host certificate for %s' % host)

    with open(args.ca_certificate, 'rb') as f:
        ca_cert_bytes = f.read()
    with open(args.ca_key, 'rb') as f:
        ca_key_bytes = f.read()

    ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes, None)
    ca_key = serialization.load_pem_private_key(ca_key_bytes, None)

    cert_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    builder = builder.public_key(cert_key.public_key())
    builder = builder.not_valid_before(datetime.datetime.now() - datetime.timedelta(days=2))
    builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(days=800))
    
    subject = [
        x509.NameAttribute(x509.NameOID.COMMON_NAME, host)
    ]
    builder = builder.subject_name(x509.Name(subject))
    builder = builder.serial_number(x509.random_serial_number())

    sans = []
    ip = try_into_ip(host)
    if ip is None:
        sans.append(x509.DNSName(host))
    else:
        sans.append(x509.IPAddress(ip))
    builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.flush()
    cert_file.close()
    
    cert_key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_key_file.write(cert_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption()
    ))
    cert_key_file.flush()
    cert_key_file.close()

    vprint('Done generating host certificate for %s' % host, args.verbose)
    log(args.logfile, 'Done generating host certificate for %s' % host)
    
    return (cert_file, cert_key_file)

hostname_ctx_dict = {}

def make_ssl_ctx_insecure(ctx):
    ctx.options &= ~ssl.OP_NO_SSLv3
    ctx.options &= ~ssl.OP_NO_SSLv2
    ctx.options &= ~ssl.OP_NO_TLSv1
    ctx.options &= ~ssl.OP_NO_TLSv1_1
    ctx.options &= ~ssl.OP_NO_TLSv1_2
    ctx.set_ciphers('ALL:@SECLEVEL=0')
    ctx.minimum_version = ssl.TLSVersion.SSLv3

def generate_ssl_default_ctx(args):
    default_ctx = hostname_ctx_dict.get(None)
    if default_ctx is None:
        default_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        (tmp_cert_file, tmp_cert_key_file) = create_host_cert(args, "temp_default")
        
        default_ctx.load_cert_chain(certfile=tmp_cert_file.name,
                            keyfile=tmp_cert_key_file.name,
                            )
        os.unlink(tmp_cert_file.name)
        os.unlink(tmp_cert_key_file.name)
        
        make_ssl_ctx_insecure(default_ctx)
        
        hostname_ctx_dict[None] = default_ctx

SSL_BLOCKING = 0

def enable_ssl_with_client(args, local_socket, fallback_sni_name):
    sni = None

    def sni_callback(sock, name, ctx):
        if name is None: # Old TLS/SSL impl
            name = fallback_sni_name
    
        nonlocal sni
        sni = name
        
        new_ctx = hostname_ctx_dict.get(name)
        
        if new_ctx is None:
            (cert_file, cert_key_file) = create_host_cert(args, name)
            new_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            new_ctx.load_cert_chain(certfile=cert_file.name, keyfile=cert_key_file.name)
            hostname_ctx_dict[name] = new_ctx
            os.unlink(cert_file.name)
            os.unlink(cert_key_file.name)
            make_ssl_ctx_insecure(new_ctx)
        sock.context = new_ctx

    try:
        default_ctx = hostname_ctx_dict.get(None)
        
        default_ctx.sni_callback = sni_callback
        local_socket = default_ctx.wrap_socket(local_socket,
                            server_side=True,
                        )
    except ssl.SSLError as e:
        print("SSL handshake failed for listening socket", str(e))
        print("=== Traceback ===")
        traceback.print_exc()
        print("===    End    ===")
        raise

    local_socket.setblocking(SSL_BLOCKING)
    if sni is None:
        print("sni_callback never called!")
        raise Exception("sni_callback never called!")
    return (local_socket, sni)

def enable_ssl_with_server(args, sni, remote_socket):
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if args.client_certificate and args.client_key:
            ctx.load_cert_chain(certfile=args.client_certificate,
                                keyfile=args.client_key,
                                )
        
        vprint('Connecting to target using SNI %s' % sni, args.verbose)
        log(args.logfile, 'Connecting to target using SNI %s' % sni)
        remote_socket = ctx.wrap_socket(remote_socket,
                                        server_hostname=sni,
                                        do_handshake_on_connect=True
                                        )
        
    except ssl.SSLError as e:
        print("SSL handshake failed for remote socket", str(e))
        print("=== Traceback ===")
        traceback.print_exc()
        print("===    End    ===")
        raise

    remote_socket.setblocking(SSL_BLOCKING)
    return remote_socket


def starttls(args, local_socket, read_sockets):
    return (args.use_ssl and
            local_socket in read_sockets and
            not isinstance(local_socket, ssl.SSLSocket) and
            is_client_hello(local_socket)
            )


def start_proxy_thread(local_socket, in_addrinfo, args, in_modules, out_modules):
    target_host = args.target_ip
    target_port = args.target_port

    local_socket_addrport = local_socket.getpeername()

    # do SOCKS5 if SOCKS5 mode enabled
    if args.use_socks5:
        socks5_conn = socks5.Connection(our_role="server")
        socks5_conn.initiate_connection()

        # get available auth methods from client
        while True:
            data = local_socket.recv(1024)
            _event = socks5_conn.recv(data)
            if _event != "NeedMoreData":
                break

        assert isinstance(_event, socks5.GreetingRequest)
        if socks5.AUTH_TYPE["NO_AUTH"] not in _event.methods:
            print('%s:%d : SOCKS5 NO_AUTH not supported by client; exiting' % in_addrinfo)
            sys.exit(101)

        # send NO_AUTH auth method to client
        _event = socks5.GreetingResponse(socks5.AUTH_TYPE["NO_AUTH"])
        data = socks5_conn.send(_event)
        local_socket.send(data)

        # get address from client
        while True:
            data = local_socket.recv(1024)
            _event = socks5_conn.recv(data)
            if _event != "NeedMoreData":
                break

        assert isinstance(_event, socks5.Request)
        if _event.cmd != socks5.REQ_COMMAND["CONNECT"]:
            print("%s:%d : SOCKS5 client didn't want to connect; exit" % in_addrinfo)
            sys.exit(102)

        target_host = str(_event.addr)
        target_port = int(_event.port)

        vprint("SOCKS5: client %s:%d wants to connect to: %s:%d" % (*local_socket_addrport, target_host, target_port), args.verbose)
        log(args.logfile, "SOCKS5: client %s:%d wants to connect to: %s:%d" % (*local_socket_addrport, target_host, target_port))

    if not is_valid_ip4(target_host) and not args.use_socks5:
        try:
            ip = socket.gethostbyname(target_host)
        except socket.gaierror:
            ip = False
        if ip is False:
            print('%s is not a valid IP address or host name' % target_host)
            sys.exit(2)
        else:
            target_ip = ip
    else:
        target_ip = target_host

    if args.use_socks5:
        # This is fake
        (binded_ip, binded_port) = ("172.17.0.1", 54321)
        _event = socks5.Response(
            socks5.RESP_STATUS["SUCCESS"],
            socks5.ADDR_TYPE["IPV4"] if type(ipaddress.ip_address(binded_ip)) is ipaddress.IPv4Address else socks5.ADDR_TYPE["IPV6"],
            binded_ip,
            binded_port
        )
        # dirty fix for https://github.com/mike820324/socks5/issues/16
        socks5_conn._conn._addr_type = _event.atyp
        socks5_conn._conn._addr = _event.addr
        socks5_conn._conn._port = _event.port

        data = socks5_conn.send(_event)
        local_socket.send(data)

    sni = None
    read_sockets, _, _ = select.select([local_socket], [], [], 1)

    if starttls(args, local_socket, read_sockets):
        try:
            local_socket, sni = enable_ssl_with_client(args, local_socket, target_host)
            vprint("SSL enabled with client %s:%d" % local_socket_addrport, args.verbose)
            log(args.logfile, "SSL enabled with client %s:%d" % local_socket_addrport)
        except ssl.SSLError as e:
            print("SSL handshake with client failed", str(e))
            log(args.logfile, "SSL handshake with client failed", str(e))
            sys.exit(4)

    # This method is executed in a thread. It will relay data between the local
    # host and the remote host, while letting modules work on the data before
    # passing it on.
    remote_socket = socks.socksocket()

    if args.proxy_ip:
        proxy_types = {'SOCKS5': socks.SOCKS5, 'SOCKS4': socks.SOCKS4, 'HTTP': socks.HTTP}
        remote_socket.set_proxy(proxy_types[args.proxy_type], args.proxy_ip, args.proxy_port)

    try:
        remote_socket.connect((target_host, target_port))
        remote_socket_addrport = remote_socket.getpeername()
        vprint('Connected to %s:%d for client %s:%d' % (*remote_socket_addrport, *local_socket_addrport), args.verbose)
        log(args.logfile, 'Connected to %s:%d for client %s:%d' % (*remote_socket_addrport, *local_socket_addrport))
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f'{time.strftime("%Y%m%d-%H%M%S")}, {target_host}:{target_port}- Connection refused')
            log(args.logfile, f'{time.strftime("%Y%m%d-%H%M%S")}, {target_host}:{target_port}- Connection refused')

            if args.use_socks5:
                # _event = socks5.Response(
                #     socks5.RESP_STATUS["CONNECTION_REFUSED"],
                #     socks5.ADDR_TYPE["IPV4"],
                #     "0.0.0.0",
                #     0
                # )
                # data = socks5_conn.send(_event)
                # local_socket.send(data)

                # Because we approve the SOCKS5 connection unconditionally,
                # instead we close the connection here
                pass

            return None
        elif serr.errno == errno.ETIMEDOUT:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f'{time.strftime("%Y%m%d-%H%M%S")}, {target_host}:{target_port}- Connection timed out')
            log(args.logfile, f'{time.strftime("%Y%m%d-%H%M%S")}, {target_host}:{target_port}- Connection timed out')

            if args.use_socks5:
                # _event = socks5.Response(
                #     socks5.RESP_STATUS["GENRAL_FAILURE"],
                #     socks5.ADDR_TYPE["IPV4"],
                #     "0.0.0.0",
                #     0
                # )
                # # dirty fix for https://github.com/mike820324/socks5/issues/16
                # socks5_conn._conn._addr_type = _event.atyp
                # socks5_conn._conn._addr = _event.addr
                # socks5_conn._conn._port = _event.port

                # data = socks5_conn.send(_event)
                # local_socket.send(data)

                # Because we approve the SOCKS5 connection unconditionally,
                # instead we close the connection here
                pass

            return None
        else:
            if args.use_socks5:
                # _event = socks5.Response(
                #     socks5.RESP_STATUS["GENRAL_FAILURE"],
                #     socks5.ADDR_TYPE["IPV4"],
                #     "0.0.0.0",
                #     0
                # )
                # # dirty fix for https://github.com/mike820324/socks5/issues/16
                # socks5_conn._conn._addr_type = _event.atyp
                # socks5_conn._conn._addr = _event.addr
                # socks5_conn._conn._port = _event.port

                # data = socks5_conn.send(_event)
                # local_socket.send(data)

                # Because we approve the SOCKS5 connection unconditionally,
                # instead we close the connection here
                pass

            for s in [remote_socket, local_socket]:
                s.close()
            raise serr

    timestamp = datetime.datetime.utcnow()
    try:
        update_module_hosts(out_modules, local_socket_addrport, remote_socket_addrport, target_host, timestamp)
        update_module_hosts(in_modules, remote_socket_addrport, local_socket_addrport, target_host, timestamp)

        # We approve the SOCKS5 connection unconditionally above (before we connect to the server)

        # if args.use_socks5:
        #     (binded_ip, binded_port) = remote_socket.getsockname()
        #     _event = socks5.Response(
        #         socks5.RESP_STATUS["SUCCESS"],
        #         socks5.ADDR_TYPE["IPV4"] if type(ipaddress.ip_address(binded_ip)) is ipaddress.IPv4Address else socks5.ADDR_TYPE["IPV6"],
        #         binded_ip,
        #         binded_port
        #     )
        #     # dirty fix for https://github.com/mike820324/socks5/issues/16
        #     socks5_conn._conn._addr_type = _event.atyp
        #     socks5_conn._conn._addr = _event.addr
        #     socks5_conn._conn._port = _event.port

        #     data = socks5_conn.send(_event)
        #     local_socket.send(data)

    except socket.error as serr:
        if serr.errno == errno.ENOTCONN:
            # kind of a blind shot at fixing issue #15
            # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
            # the connection is not in a useful state anymore
            for s in [remote_socket, local_socket]:
                s.close()
            return None
        else:
            for s in [remote_socket, local_socket]:
                s.close()
            print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
            raise serr

    # This loop ends when no more data is received on either the local or the
    # remote socket
    running = True
    if sni is not None:
        try:
            remote_socket = enable_ssl_with_server(args, sni, remote_socket)
            vprint("SSL enabled with server %s:%d (client: %s:%d)" % (*remote_socket_addrport, *local_socket_addrport), args.verbose)
            log(args.logfile, "SSL enabled with server %s:%d (client: %s:%d)" % (*remote_socket_addrport, *local_socket_addrport))
        except ssl.SSLError as e:
            print("SSL handshake with server failed", str(e))
            log(args.logfile, "SSL handshake with server failed", str(e))
            sys.exit(3)

    remote_ssl_wants_read = False
    local_ssl_wants_read = False
    while running:
        sockets_to_read = []
        if remote_ssl_wants_read:
            remote_ssl_wants_read = False
        else:
            sockets_to_read.append(remote_socket)
        if local_ssl_wants_read:
            local_ssl_wants_read = False
        else:
            sockets_to_read.append(local_socket)
            
        read_sockets, _, _ = select.select(sockets_to_read, [], [], 0.1)

        for sock in read_sockets:
            try:
                peer = sock.getpeername()
            except socket.error as serr:
                if serr.errno == errno.ENOTCONN:
                    # kind of a blind shot at fixing issue #15
                    # I don't yet understand how this error can happen, but if it happens I'll just shut down the thread
                    # the connection is not in a useful state anymore
                    for s in [remote_socket, local_socket]:
                        s.close()
                    running = False
                    break
                else:
                    print(f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in start_proxy_thread")
                    raise serr

            data, err = receive_from(sock)
            if err is not None:
                if isinstance(err, ssl.SSLWantReadError):
                    if len(data) == 0:
                        vprint("len(data) == 0 with SSLWantReadError, with %s:%d" % peer, args.verbose)
                        log(args.logfile, "len(data) == 0 with SSLWantReadError, with %s:%d" % peer)
                        if sock == local_socket:
                            local_ssl_wants_read = True
                        else:
                            remote_ssl_wants_read = True
                        continue
                else:
                    raise err

            if sock == local_socket:
                if len(data):
                    log(args.logfile, b'< < < out\n' + data)
                    if out_modules is not None:
                        data = handle_data(data, timestamp, out_modules,
                                           args.no_chain_modules,
                                           False,  # incoming data?
                                           args.verbose)
                    send_to(remote_socket, data.encode() if isinstance(data, str) else data, peer, args)
                else:
                    vprint("Connection from local client %s:%d closed" % peer, args.verbose)
                    log(args.logfile, "Connection from local client %s:%d closed" % peer)
                    handle_close(timestamp, out_modules, False, args.verbose)
                    remote_socket.close()
                    running = False
                    break
            elif sock == remote_socket:
                if len(data):
                    log(args.logfile, b'> > > in\n' + data)
                    if in_modules is not None:
                        data = handle_data(data, timestamp, in_modules,
                                           args.no_chain_modules,
                                           True,  # incoming data?
                                           args.verbose)
                    send_to(local_socket, data.encode() if isinstance(data, str) else data, peer, args)
                else:
                    vprint("Connection to remote server %s:%d closed" % peer, args.verbose)
                    log(args.logfile, "Connection to remote server %s:%d closed" % peer)
                    handle_close(timestamp, in_modules, True, args.verbose)
                    local_socket.close()
                    running = False
                    break


def log(handle, message, message_only=False):
    # if message_only is True, only the message will be logged
    # otherwise the message will be prefixed with a timestamp and a line is
    # written after the message to make the log file easier to read
    if not isinstance(message, bytes):
        message = bytes(message, 'ascii')
    if handle is None:
        return
    if not message_only:
        logentry = bytes("%s %s\n" % (time.strftime('%Y%m%d-%H%M%S'), str(time.time())), 'ascii')
    else:
        logentry = b''
    logentry += message
    if not message_only:
        logentry += b'\n' + b'-' * 20 + b'\n'
    handle.write(logentry)


def vprint(msg, is_verbose):
    # this will print msg, but only if is_verbose is True
    if is_verbose:
        print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)


def main():
    args = parse_args()
    if args.list is False and args.help_modules is None:
        if not args.use_socks5:
            if not args.target_ip:
                print('Target IP is required: -ti')
                sys.exit(6)
            if not args.target_port:
                print('Target port is required: -tp')
                sys.exit(7)

    if ((args.client_key is None) ^ (args.client_certificate is None)):
        print("You must either specify both the client certificate and client key or leave both empty")
        sys.exit(8)

    if args.logfile is not None:
        try:
            args.logfile = open(args.logfile, 'ab', 0)  # unbuffered
        except Exception as ex:
            print('Error opening logfile')
            print(ex)
            sys.exit(4)

    if args.list:
        list_modules()
        sys.exit(0)

    if args.help_modules is not None:
        print_module_help(args.help_modules)
        sys.exit(0)

    if args.listen_ip != '0.0.0.0' and not is_valid_ip4(args.listen_ip):
        try:
            ip = socket.gethostbyname(args.listen_ip)
        except socket.gaierror:
            ip = False
        if ip is False:
            print('%s is not a valid IP address or host name' % args.listen_ip)
            sys.exit(1)
        else:
            args.listen_ip = ip

    # if args.target_ip is not None:
    #     if not is_valid_ip4(args.target_ip):
    #         try:
    #             ip = socket.gethostbyname(args.target_ip)
    #         except socket.gaierror:
    #             ip = False
    #         if ip is False:
    #             print('%s is not a valid IP address or host name' % args.target_ip)
    #             sys.exit(2)
    #         else:
    #             args.target_ip = ip

    if args.in_modules is not None:
        in_modules = generate_module_list(args.in_modules, incoming=True, verbose=args.verbose)
    else:
        in_modules = None

    if args.out_modules is not None:
        out_modules = generate_module_list(args.out_modules, incoming=False, verbose=args.verbose)
    else:
        out_modules = None

    if args.use_ssl:
        generate_ssl_default_ctx(args)

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        proxy_socket.bind((args.listen_ip, args.listen_port))
    except socket.error as e:
        print(e.strerror)
        sys.exit(5)

    proxy_socket.listen(100)
    log(args.logfile, str(args))
    # endless loop until ctrl+c
    try:
        while True:
            ready, _, _ = select.select([proxy_socket], [], [], 0.2)
            if ready:
                in_socket, in_addrinfo = proxy_socket.accept()
            else:
                continue
            vprint('Connection from %s:%d' % in_addrinfo, args.verbose)
            log(args.logfile, 'Connection from %s:%d' % in_addrinfo)
            proxy_thread = threading.Thread(target=start_proxy_thread,
                                            args=(in_socket, in_addrinfo, args, in_modules,
                                                  out_modules))
            log(args.logfile, "Starting proxy thread " + proxy_thread.name)
            proxy_thread.start()
    except KeyboardInterrupt:
        log(args.logfile, 'Ctrl+C detected, exiting...')
        print('\nCtrl+C detected, exiting...')
        os._exit(0)


if __name__ == '__main__':
    main()
