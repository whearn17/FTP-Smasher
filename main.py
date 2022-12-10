# FTP Smasher
# Author: Will Hearn

import os
import math
import numpy
import ftplib
import random
import argparse
import traceback
import threading
import multiprocessing


VERSION = "0.0.1"

cpu_cores = math.floor(multiprocessing.cpu_count() / 2)
num_threads = 100
timeout = 10

processes = []
threads = []
ip_list = []
servers_found = []

ip_input_file = ""

# Locks
t_ip_list_lock = threading.Lock()


# Clear screen
def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


# Function init_args initializes
# arguments for the program
def init_args():
    parser = argparse.ArgumentParser(prog="FTP Smasher")

    # Input IP file argument
    parser.add_argument("-i", "--input-file", type=str,
                        help="Scan a list of IPs from a file")

    return parser.parse_args()


# Function parse_args parses command
# line arguments
def parse_args(arguments):
    global ip_input_file

    # Input IP file argument
    if arguments.input_file:
        ip_input_file = arguments.input_file
        read_ips()
    else:
        print("No IP File Specified...\nExiting")
        exit(0)


# Read IPs in from a file
def read_ips():
    print("Reading IPs...")
    with open(ip_input_file, "r") as f:
        for line in f:
            ip_list.append(line.rstrip())
    f.close()
    random.shuffle(ip_list)


# Initialize processes
def init_processes():
    # Split up ip list into many arrays
    ip_list_split = numpy.array_split(ip_list, cpu_cores)

    # Rebuild lists and send off to target process
    for i in range(cpu_cores):
        ip_list_local = ip_list_split[i].tolist()
        p = multiprocessing.Process(target=p_main, args=(ip_list_local,))
        p.start()
        processes.append(p)


# Main method for processes
def p_main(ip_list_local):

    # Initialize global variables
    init_globals(ip_list_local)

    # Initialize threads
    for i in range(num_threads):
        t = threading.Thread(target=t_main)
        t.start()
        threads.append(t)


# Function init_globals takes variables
# passed by the original python process
# and sets them inside of the current
# process
def init_globals(ip_list_local):
    global ip_list

    ip_list = ip_list_local


# Main method for threads
def t_main():
    # Make sure ip list has work left
    while len(ip_list) > 0:
        try:
            # Pop off list with mutex
            with t_ip_list_lock:
                ip = ip_list.pop()

            # Attempt to login
            login(ip)
        except Exception as e:  # Generic clause for debugging
            print(e)


# Function login attempts to
# login to an ftp server
def login(ftp_host):
    try:
        # Create a new FTP client
        ftp = ftplib.FTP(ftp_host, timeout=timeout)

        # Attempt to login to the FTP server
        ftp.login("anonymous", "password")

        # If the server is found add it to list
        servers_found.append(ftp_host)

        # If the login was successful, log a message
        print(f"Successfully logged in to {ftp_host}")

    except ftplib.error_perm:  # Login failed
        pass
    except ftplib.error_temp:
        pass
    except ftplib.error_proto:
        pass
    except ftplib.error_reply:
        pass
    except UnicodeDecodeError:
        pass
    except EOFError:
        pass
    except ConnectionRefusedError:
        pass
    except ConnectionResetError:  # RST
        pass
    except TimeoutError:  # Socket timeout
        pass
    except Exception as e:  # Generic catch for debugging
        print(traceback.print_exc())


if __name__ == "__main__":
    # Clear screen
    cls()

    # Initialize arguments
    args = init_args()

    # Parse command line args
    parse_args(args)

    # Initialize processes
    init_processes()
