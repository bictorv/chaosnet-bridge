# Chaosnet server for NAME protocol (what is otherwise known as finger, which is a different protocol on Chaosnet)
import socket, io
import sys, subprocess, threading
import re, string

finger_program = "/usr/bin/finger"
server_address = '/tmp/chaos_stream'
debug = False

def switch_interpreter(x):
    # Translate /W to -l
    if x.startswith(b'/'):
        if x == b'/W':
            return b'-l'
        # ignore other switches
    else:
        return x

def give_finger_response(sock, args):
    # Run finger and capture the output
    pargs = [finger_program,'-s']+list(filter(lambda x: x is not None, map(switch_interpreter, args)))
    if debug:
        print("Running {!s}".format(pargs),file=sys.stderr)
    r = subprocess.run(pargs, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    # Translate to lispm characters, kind of - should also handle Unicode de-translation?
    rout = r.stdout.translate(bytes.maketrans(b'\t\n\f\r',b'\211\215\214\212'))
    # Send the response, and close the socket
    sock.sendall(rout)
    sock.close()

def name_server():
    # Create a Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    try:
        sock.connect(server_address)
    except socket.error as msg:
        print(msg)
        sys.exit(1)

    # Set up a listener for NAME
    sock.sendall(b'LSN NAME')

    try:
        # Get a request from the socket
        data = sock.recv(128)
        # Strip newlines, split at blanks
        args = data.rstrip().split(b' ')
        if args[0] == b"RFC":
            if debug:
                print('got RFC from {!s} with args {!r}'.format(args[1],args[2:]))
            # Accept the request
            sock.sendall(b"OPN\r\n")
            t = threading.Thread(target=give_finger_response,args=(sock, args[2:])).start()
        else:
            sock.sendall(b'CLS Bad request\r\n')
            sock.close()
    except socket.error as msg:
        print(msg)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Chaosnet NAME server')
    parser.add_argument("-d",'--debug',dest='debug',action='store_true',
                            help='Turn on debug printouts')
    parser.add_argument("-p",'--program',nargs=1,dest='program',
                            help='The program to run to get finger information')
    args = parser.parse_args()
    if args.program:
        finger_program = args.program[0]
        print("Using {!s} for getting finger information".format(finger_program))
    if args.debug:
        print("Turning debug on")
        debug = True

    # Handle many requests
    while True:
        name_server()
