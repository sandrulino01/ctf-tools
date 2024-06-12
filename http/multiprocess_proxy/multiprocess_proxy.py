import asyncio
import os
import sys
import re
import multiprocessing
import time

# Because of my skill issues(?)
# You may need to remove this comment and put your path
#sys.path.append("<path>/pyjson5")
# You can find the path with pip3 show pyjson5 in Location
# [...]
# Location: /usr/lib/python3/dist-packages
# [...]
import pyjson5 # pip3 install pyjson5==1.6.6

usage_text = '''
####
#
# Proxy (refactoring)
# Made by: sandrulino - Last update: 04 june 2024
##########################################################################################################################
# 
# If You are using docker, use this proxy outside docker NOT inside! (because of enable_proxy & disable_proxy functions)
# Sudo permissions are needed.
#
# Usage:
# python3 multiprocess_proxy.py
# \t[ -h | -help | -u | -usage ] # Shows this message
# \t[-ip] # Starts proxy server with the given ip. If no ip is given, a default one is used (10.0.2.15). If services.json is not found a default one is created.
# \t[-reset] # After a confirmation, services.json is resetted
#
# services.json infos:
# Every time services.json has been changed You need to use the "update" command
# You can create as many services as You want but service names MUST be unique
# You may create new types but they MUST exist in type_banned and in type_match_banned
# Port MUST be unique between ports and proxyports
# Proxyport MUST be unique between proxyports and ports
# You can't edit port and / or proxyport after that service has been started
#  If You need to change them, You may restart proxy or edit the name too: the current service will be closed and a new one will be created with the new port and / or proxyport (and name, You may want to change back again the name only)
#
# Service names (for example PlsDontPwnMe): indicates the name of the service. MUST be unique
# type: indicates the type of the service. Services are filtered with rules of its own type (if they exist)
# banned: indicates banned strings. You may use hex syntax ("\\x30" --> 0). Services are filtered by his own banned strings list. Checks are NOT case sensitive
# match_banned: indicates banned regular expressions. Services are filtered by his own banned regular expressions list
# port: indicates the service's port. You may check used port via "sudo lsof -i -P -n | grep LISTEN" or "sudo docker ps"
# proxyport: indicates the service's proxy port. You may use ports between 49152 and 65535
# 
# gen_banned: indicates general banned strings. You may use hex syntax ("\\x30" --> 0). Every service is filtered by this banned strings list. Checks are NOT case sensitive
# gen_match_banned: indicates general banned regular expressions. Every service is filtered by this general banned regular expressions list
#
# type_banned: indicates banned strings for a service's type. You may use hex syntax ("\\x30" --> 0). Only services with the same type are filtered by this banned strings list. Checks are NOT case sensitive
# type_match_banned: indicates banned regular expressions for a service's type. Only services with the same type are filtered by this banned regular expressions list
#
####
'''
##########################################################################################################################
# Stuff to color terminal
tab = ""

class colors:
    GREEN = '\033[92m' # OK
    YELLOW = '\033[93m' # WARNING
    RED = '\033[91m' # FAIL
    BLUE = '\u001b[34m' # INFO
    RESET = '\033[0m' # RESET COLOR
    BOLD = "\033[1m" # BOLD

def colored_print(my_string, color_me, text_color):
    splitted = my_string.split(color_me)
    print(splitted[0] + colors.BOLD + text_color + str(color_me) + colors.RESET + splitted[1])

##########################################################################################################################

class my_client_handler():

    def __init__(self, service_name, service, ban_type, ban_match_type, gen_ban, gen_match_ban, check4updates):
        self.service_name = service_name
        self.service = service
        self.type_banned = ban_type
        self.type_match_banned = ban_match_type
        self.gen_banned = gen_ban
        self.gen_match_banned = gen_match_ban
        self.check4updates = check4updates
        self.bans = 0
        self.err = 0
        self.acpt = 0
        self.rcv = 0
        self.denied = False

    # Loop function
    async def handle_client(self, local_reader, local_writer):

        # Check if updates are needed
        if self.check4updates[self.service_name] == "update":
            colored_print("[" + self.service_name + "] Updating banning rules. . .", self.service_name, colors.BLUE)
            try:
                services_file = open("services.json",'r')
                json_infos = pyjson5.load(services_file)
                services_file.close()
                self.service = json_infos["services"][self.service_name]
                self.gen_banned = json_infos["gen_banned"]
                self.gen_match_banned = json_infos["gen_match_banned"]
                self.type_banned = json_infos["type_banned"][self.service["type"]]
                self.type_match_banned = json_infos["type_match_banned"][self.service["type"]]
                colored_print("[" + self.service_name + "] Banning rules have been updated!", self.service_name, colors.GREEN)
            except:
                colored_print("[" + self.service_name + "] Something went wrong. No rules have been changed. Please check services.json before updating again", self.service_name, colors.RED)
            
        try:

            port = local_writer.get_extra_info("socket").getsockname()[1] #Getting proxy (request) port

            srcport = None # Real service port

            # Getting service by proxy port
            if self.service["proxyport"] == port:
                srcport = self.service["port"]

            self.rcv += 1
            colored_print("[" + self.service_name + "] Received ("+ str(self.rcv) +")" , self.service_name, colors.YELLOW)
            
            # Port / service not found ==> :( Drop
            # ATTENTION: You may get this error if You set bad services. The approach remains blacklist
            if srcport is None:
                self.err += 1
                colored_print("[" + self.service_name + "] Proxy port ("+ str(self.err) +"): " + str(port) + " not found. You may set bad services. Please do not change services' port and proxy port after starting proxy also", self.service_name, colors.RED)
                return

            # Trying to access a banned port == >:D Drop
            if self.service["type"] == "ban":
                self.bans += 1
                colored_print("[" + self.service_name + "] Banned port ("+str(self.bans)+"): " + str(self.service["port"]), self.service_name, colors.RED)
                return        

            remote_reader, remote_writer = await asyncio.open_connection(
                "127.0.0.1", srcport)

            # Debug porpuse
            #print(local_writer.get_extra_info("socket"))
            self.denied = False

            pipe1 = self.filter_pipe(local_reader, remote_writer, self.service)
            
            pipe2 = self.pipe(remote_reader, local_writer)

            await asyncio.gather(pipe1, pipe2)

            if(self.denied is not True):
                self.acpt += 1
                colored_print("[" + self.service_name + "] Accepted ("+ str(self.acpt) +")", self.service_name, colors.GREEN)
            else:
                self.denied = False

        finally:
            local_writer.close()

    async def filter_pipe(self, reader, writer, service):
        try:
            while not reader.at_eof():
                buf = await reader.read(2048)

                # Checking rules, everything must be in byte ( str.encode(b) )
                # Connection is closed by raise

                # Checking general banned strings
                for b in self.gen_banned:
                    if byte_to_uppercase(str.encode(b)) in byte_to_uppercase(buf):
                        self.bans += 1
                        colored_print("[" + self.service_name + "] General banned string has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise
                        
                # Checking general regular expression
                for b in self.gen_match_banned:
                    z = re.compile(str.encode(b))
                    z = z.match(buf)
                    if z != None:
                        self.bans += 1
                        colored_print("[" + self.service_name + "] General banned regex has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise

                for b in self.type_banned:
                    if byte_to_uppercase(str.encode(b)) in byte_to_uppercase(buf):
                        self.bans += 1
                        colored_print("[" + self.service_name + "] Type banned string has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise
                
                # Checking type banned regex
                for b in self.type_match_banned:
                    z = re.compile(str.encode(b))
                    z = z.match(buf)
                    if z != None:
                        self.bans += 1
                        colored_print("[" + self.service_name + "] Type banned regex has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise

                # Checking services banned strings
                for b in self.service["banned"]:
                    if byte_to_uppercase(str.encode(b)) in byte_to_uppercase(buf):
                        self.bans += 1
                        colored_print("[" + self.service_name + "] Service's banned string has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise

                # Checking services banned regex  
                for b in self.service["match_banned"]:
                    z = re.compile(str.encode(b))
                    z = z.match(buf)
                    if z != None:
                        self.bans += 1
                        colored_print("[" + self.service_name + "] Service's banned regex has been found ("+ str(self.bans) +"): " + b, self.service_name, colors.RED)
                        raise

                writer.write(buf)

        except Exception:
            # Debug porpuse
            #import traceback
            #traceback.print_exc()
            self.denied = True
        finally:
            writer.close()

    async def pipe(self, reader, writer):
        try:
            while not reader.at_eof():
                buf = await reader.read(2048)
                writer.write(buf)
        finally:
            writer.close()

# Byte to uppercase
def byte_to_uppercase(byte_to_upper):
    out = b""
    for b in byte_to_upper:
        if b <= 122 and b >= 97:
            out += chr(b-32).encode()
        else:
            out += chr(b).encode()
    return out

# Generate iptables. You may don't need to change this
def build_cmds(services, src, proxyip):
    cmds = []
    for s in services:
        cmds.append("PREROUTING --dst %s -p tcp --dport %s -j DNAT --to-destination %s:%s" % ( src, services[s]["port"], proxyip, services[s]["proxyport"]))
        cmds.append("POSTROUTING -p tcp --dst %s --dport %s -j SNAT --to-source %s" % ( proxyip, services[s]["proxyport"], src)) #this may do nothing, this is used when proxyServer is not on the vulnbox
        cmds.append("OUTPUT --dst %s -p tcp --dport %s -j DNAT --to-destination %s:%s" % ( src, services[s]["port"], proxyip, services[s]["proxyport"]))

    return cmds

# Enable proxy via iptables
def enable_proxy(services, src, proxyip):
    cmds = build_cmds(services, src, proxyip)
    for cmd in cmds:
        cmd = "sudo iptables -t nat -I " + cmd
        os.system(cmd)

# Disable proxy via iptables
def disable_proxy(services, src, proxyip):
    cmds = build_cmds(services, src, proxyip)
    for cmd in cmds:
        cmd = "sudo iptables -t nat -D " + cmd 
        os.system(cmd)

# Process function
def proxy_service(service_name, service, ban_type, ban_match_type, gen_ban, gen_match_ban, check4updates, proxyip):

    colored_print("[PR0XY] Creating " + service_name + " proxy server. . .", "PR0XY", colors.BLUE)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    ch = my_client_handler(service_name, service, ban_type, ban_match_type, gen_ban, gen_match_ban, check4updates)
    server = loop.run_until_complete(asyncio.start_server(ch.handle_client, proxyip, service["proxyport"])) #riuscire a passare parametri qua e in teoria ho fatto

    colored_print("[PR0XY] Starting " + service_name + " proxy server. . .", "PR0XY", colors.BLUE)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        colored_print("[PR0XY] Closing " + service_name + "proxy server. . .", "PR0XY", colors.BLUE)
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
        colored_print("[PR0XY] " + service_name + " closed!", "PR0XY", colors.BLUE)

def reset_services_json():
    try:
        services_json = open('services.json', 'w')
        example_services = '{\n\t"services": {\n\t\t"PlsDontPwnMe": {\n\t\t\t"type": "web",\n\t\t\t"banned": ["PAYLOAD1", "PAYLOAD2"],\n\t\t\t"match_banned": [],\n\t\t\t"port": 8000,\n\t\t\t"proxyport": 50000\n\t},\n\t\t"You can\'t beat me": {\n\t\t\t"type": "pwn",\n\t\t\t"banned": ["\\x50\\x41\x59\\x4c\\x4f\\x41\\x44\\x33"],\n\t\t\t"match_banned": [],\n\t\t\t"port": 9000,\n\t\t\t"proxyport": 50001\n\t},\n\t\t"Database port": {\n\t\t\t"type": "ban",\n\t\t\t"banned": [],\n\t\t\t"match_banned": [],\n\t\t\t"port": 10000,\n\t\t\t"proxyport": 50002\n\t}\n},\n\t"gen_banned": ["User-Agent: python-requests", "User-Agent: curl"],\n\t"gen_match_banned": ["(.)\\\\1{49,}","(.)\\\\1{49,}\\xa8\\xc3\\x04\\x08"],\n\t"type_banned": {\n\t\t"crypto": [],\n\t\t"forensics": [],\n\t\t"pwn": ["${IFS}","$IFS"],\n\t\t"reversing": [],\n\t\t"web": ["select","union"," or ","where"]\n\t},\n\t"type_match_banned": {\n\t\t"crypto": [],\n\t\t"forensics": [],\n\t\t"pwn": [],\n\t\t"reversing": [],\n\t\t"web": []\n\t}\n}\n'
        services_json.write(example_services)
        services_json.close()
    except:
        colored_print("[PR0XY] An error occurred while resetting services.json", "PR0XY", colors.RED)
        exit(1)

##########################################################################################################################
### MAIN ###

def main(): 
    
    src = "10.0.2.15"
    ip_service = "127.0.0.1"
    proxyip = src
    reset = False
    ip2test = None

    if len(sys.argv) > 1:
        
        for i in range(1,len(sys.argv)):
            
            if sys.argv[i][:2] == "-h" or sys.argv[i][:2] == "-u":
                print(usage_text)
                return
            
            if "-ip" == sys.argv[i]:
                if i+1 >= len(sys.argv):
                    print("Please provide an ip\n" + usage_text)
                    return
                ip2test = sys.argv[i+1]
                ip2test_splitted = ip2test.split(".")
                if len(ip2test_splitted) != 4 or not ip2test_splitted[0].isnumeric() or not ip2test_splitted[1].isnumeric() or not ip2test_splitted[2].isnumeric() or not ip2test_splitted[3].isnumeric() or int(ip2test_splitted[0]) > 255 or int(ip2test_splitted[1]) > 255 or int(ip2test_splitted[2]) > 255 or int(ip2test_splitted[3]) > 255:
                    print("Please provide a valid ip: <0-255>.<0-255>.<0-255>.<0-255>")
                    return
                src = proxyip = ip2test
                continue

            if "-reset" == sys.argv[i]:
                reset = True
                continue

    if ip2test is None:
        colored_print("[PR0XY] Warning, proxy is starting with default ip (" + src + ")", "PR0XY", colors.YELLOW)

    colored_print("[PR0XY] Starting. . .", "PR0XY", colors.BLUE)
    json_exists = os.path.exists("services.json")
    
    if json_exists and reset:
        ans = ""
        while ans != "YeS!" and ans != "no":
            colored_print("[PR0XY] Warning, services settings already exists, are You sure to reset them? ( YeS! | no )", "PR0XY", colors.YELLOW)
            ans = input()
        if ans == "YeS!":
            reset_services_json()
            
    if not json_exists:
        colored_print("[PR0XY] Warning, proxy has been started with example services. Consider to edit services.json", "PR0XY", colors.YELLOW)
        reset_services_json()    
    
    check4updates = multiprocessing.Manager().dict() # check4updates[service_name] = "work" | "update"

    try:
        try:
            services_file = open("services.json", 'r')
            services = pyjson5.load(services_file)
            services_file.close()
        except:
            colored_print("[PR0XY] An error occurred while reading services.json. Please check services.json", "PR0XY", colors.RED)
            exit(1)

        threads = {} # Dict of "threads" (they are process). There isn't thread.stop() in python, so process are used ( they have process.terminate() )

        # For each service found, a process is created
        for service_name in services['services']:

            check4updates[service_name] = "work"

            if services['services'][service_name]['type'] != "ban":
            	threads[service_name] = multiprocessing.Process(target=
            	proxy_service, args=(service_name, services['services'][service_name], services['type_banned'][services['services'][service_name]['type']], services['type_match_banned'][services['services'][service_name]['type']], services['gen_banned'], services['gen_match_banned'], check4updates, proxyip, ))
            else:
                threads[service_name] = multiprocessing.Process(target=proxy_service, args=(service_name, services['services'][service_name], None, None, None, None, check4updates, proxyip, ))
            threads[service_name].start()
    
        enable_proxy(services['services'], src, proxyip)
        
        colored_print("[PR0XY] Proxy ON", "PR0XY", colors.GREEN)

        input_cmd = ""
        while True:

            colored_print("[PR0XY] Enter update when services.json has been updated!", "PR0XY", colors.BLUE)
            input_cmd = input("")
            if input_cmd == "update":
                
                try:
                    services_file = open("services.json",'r')
                    new_services = pyjson5.load(services_file)
                    services_file.close()
                    
                    remove_me = []
                    # For each service active
                    for service_name in threads.keys():
                        # If is not in json file
                        if service_name not in new_services['services']:
                            # Disable it and stop it
                            colored_print("[PR0XY] Closing " + service_name + " proxy server. . ." , "PR0XY", colors.BLUE)
                            disable_proxy({'services': services['services'][service_name]}, src, proxyip)
                            threads[service_name].terminate()
                            colored_print("[PR0XY] " + service_name + " proxy server has been closed!" , "PR0XY", colors.BLUE)
                            remove_me.append(service_name)               

                    for service_name in remove_me:
                        del threads[service_name]
                            
                    # For each service found
                    for service_name in new_services['services']:
                        # If already exists, check for updates needed
                        if service_name in threads.keys():
                            check4updates[service_name] = "update"
                            colored_print("[PR0XY] " + service_name + " is updating banning rules. . ." , "PR0XY", colors.BLUE)
                        # If doesnt exists, his process is created and started
                        elif service_name not in threads.keys():
                            check4updates[service_name] = "work"
                            
                            if new_services['services'][service_name]['type'] != "ban":
                                threads[service_name] = multiprocessing.Process(target=proxy_service, args=(service_name, new_services['services'][service_name], new_services['type_banned'][new_services['services'][service_name]['type']], new_services['type_match_banned'][new_services['services'][service_name]['type']], new_services['gen_banned'], new_services['gen_match_banned'], check4updates, proxyip, ))
                            else:
                                threads[service_name] = multiprocessing.Process(target=proxy_service, args=(service_name, new_services['services'][service_name], None, None, None, None, check4updates, proxyip, ))  
                            
                            threads[service_name].start()
                            enable_proxy({"services": new_services['services'][service_name]}, src, proxyip)

                    services = new_services

                except:
                    colored_print("[PR0XY] Something went wrong while updating services. You may check services.json and may restart proxy" , "PR0XY", colors.RED)
            
    except KeyboardInterrupt:
        colored_print("[PR0XY] Ctrl-C detected" , "PR0XY", colors.BLUE)
        colored_print("[PR0XY] Stopping. . ." , "PR0XY", colors.BLUE)

    except Exception as e:
        colored_print("[PR0XY] Something went wrong =(", "PR0XY", colors.BLUE)
        colored_print("[PR0XY] Stopping. . ." , "PR0XY", colors.BLUE)

    finally:
        disable_proxy(services['services'], src, proxyip)
        for t in threads:
            threads[t].terminate()
        
        colored_print("[PR0XY] Proxy OFF", "PR0XY", colors.GREEN)
        colored_print("[PR0XY] Done!" , "PR0XY", colors.GREEN)
        
  
if __name__ == "__main__":
    main()
else:
    colored_print("[PR0XY] You must run this file as main file. Please run python3 multiprocess_proxy.py -h for more infos" , "PR0XY", colors.RED)
    exit(1)
