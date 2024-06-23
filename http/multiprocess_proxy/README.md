
# multiprocess_proxy.py

Simple Python script that allows you to proxy http requests to multiple services at the same time and block unwanted requests

## Features

- Multiple ban rules applicable to different services at the same time (multi process script)
- Run-time editable ban list rules
- Ban list saved and loaded on/from file
- Case unsensitive string match ban list
- Regex match ban list
- Hex syntax compatible
- Different types of ban rules (more info in [Usage/Examples](#UsageExamples))

## Installation

You can install requirements via

```bash
pip3 install -r requirements.txt
```

or

```bash
pip3 install pyjson5==1.6.6
```

#### IMPORTANT

Because of my skill issues(?) 

If You run python3 with sudo, You may need to remove this comment and put your path
```python
#sys.path.append("<path>/pyjson5")
```
You can find the path with `pip3 show pyjson5` in Location

```
[...]
Location: /usr/lib/python3/dist-packages
[...]
```

The code would become this

```python
sys.path.append("/usr/lib/python3/dist-packages/pyjson5")
```

In alternative You may run the script without sudo permissions, They will be asked after startup

## How to run

Get the multiprocess_proxy folder and go to the project directory

Install dependencies: You can check how [here](#Installation)

You may check if everything is fine with -h parameter. Usage text should appear with no errors.
```bash
sudo python3 multiprocess_proxy.py -h
```

To start the proxy, You may use your machine ip but it's **IMPORTANT** that You **don't use 127.0.0.1 (or localhost and similar)**. You may check your machine ip via

```bash
ifconfig
```

You need to access to the service and start the proxy **with it**. 

#### IMPORTANT infos
Sudo permissions are needed. If You are using docker, use this proxy outside docker NOT inside!

You can start the proxy with
```bash
sudo python3 multiprocess_proxy.py -ip <ip>
```

If not found, a default configuration file `services.json` is gonna be created. You can find some example on how to edit that / or create a new one [here](#UsageExamples)

You can reset `services.json` anytime via `-reset` parameter like
```bash
sudo python3 multiprocess_proxy.py -ip <ip> -reset
```

If you need to kill the proxy You may use this bash script
```bash
#!/bin/bash

# Find processes' ID
pids=$(pgrep -f "python3 multiprocess_proxy.py")

# Kill processes
if [ ! -z "$pids" ]; then
  echo "PIDs killed: $pids"
  kill $pids
else
  echo "No processes found"
fi
```
Please remember to `chmod +x thiscript.sh` and run it via `./thiscript.sh`

**DO NOT kill** the proxy with the `-9` flag: iptables need to be cleaned up before closing the proxy otherwise, a manual iptables restore will be necessary! To do so, You may use one of the snapshots created by the proxy

If the `-snapshot` argument is NOT given, a snapshot of your iptables will be created in `snapshots/iptables-snapshot-%Y-%m-%d-%H:%M:%S.txt` before starting the proxy. You can also create one yourself via `sudo iptables-save > iptables-snapshot.txt`

You can restore a snapshot anytime via: `sudo iptables-restore < iptables-snapshot-<timestamp>.txt`

## Running Tests

To run tests, run the following command

Create a (or multiple) service(s) as You want. For quick tests You can use Python simple server

```bash
python3 -m http.server 8000
```

and / or php

```bash
php -S 0.0.0.0:9000
```

Then start the proxy: You may check how to do that [here](#How-to-run)

You can try a quick check doing 
```bash
curl <ip>:8000
```
The response should be `curl: (52) Empty reply from server`

Now that You have a (or multiple) service(s) and everything is working, You may check `services.json` and edit the file properly. Then You may enter `update` to update proxy rules. You can find some example on how to do that [here](#UsageExamples)
## Usage/Examples

In this example I have 3 services:
- PlsDontPwnMe: a web service (`php -S 0.0.0.0:8000`)
- You can't beat me: a pwn service (`python3 -m http.server 9000`)
- Database port: an exposed port (`10000`) that I want to block access to

The proxy uses a `services.json` file. This is an example.
```
{
	"services": {
		"PlsDontPwnMe": {
			"type": "web",
			"banned": ["PAYLOAD1", "PAYLOAD2"],
			"match_banned": [],
			"port": 8000,
			"proxyport": 50000
	},
		"You can't beat me": {
			"type": "pwn",
			"banned": ["\x50\x41Y\x4c\x4f\x41\x44\x33"],
			"match_banned": [],
			"port": 9000,
			"proxyport": 50001
	},
		"Database port": {
			"type": "ban",
			"banned": [],
			"match_banned": [],
			"port": 10000,
			"proxyport": 50002
	}
},
	"gen_banned": ["User-Agent: python-requests", "User-Agent: curl"],
	"gen_match_banned": ["(.)\\1{49,}","(.)\\1{49,}\xa8\xc3\x04\x08"],
	"type_banned": {
		"crypto": [],
		"forensics": [],
		"pwn": ["${IFS}","$IFS"],
		"reversing": [],
		"web": ["select","union"," or ","where"]
	},
	"type_match_banned": {
		"crypto": [],
		"forensics": [],
		"pwn": [],
		"reversing": [],
		"web": []
	}
}
```
Prevents requests and drops responses to:
- Every request made with user agent `python-requests` or `curl` (be careful, this check is not done with request headers but It is with string match so a request with written `User-Agent: python-requests` or `User-Agent: curl` anywhere is blocked)
- Every request with these regex `(.)\\1{49,}` or `(.)\\1{49,}\xa8\xc3\x04\x08`
- Requests to `pwn` services with `${IFS}` or `$IFS`
- Requests to `web` services with `select` or `union` or `or` (with spaces before and after) or `where`
- Requests to `PlsDontPwnMe` with `PAYLOAD1` or `PAYLOAD2`
- Requests to `You can't beat me` with `\x50\x41Y\x4c\x4f\x41\x44\x33`

#### All `services.json` info

- Service names (for example `PlsDontPwnMe`): indicates the name of the service
- `type`: indicates the type of the service. Services are filtered with rules of its own type (if they exist)
- `banned`: indicates banned strings. You may use hex syntax (`\x30` becomes `0`). Services are filtered by his own banned strings list. Checks are NOT case sensitive
- `match_banned`: indicates banned regular expressions. Services are filtered by his own banned regular expressions list
- `port`: indicates the service's port. You may check used port via
```bash
sudo lsof -I -P -n | grep LISTEN
```
or If your services are in docker
```bash
sudo docker ps
```
- `proxyport`: indicates the service's proxy port. You may use ports between 49152 and 65535

#### IMPORTANT `services.json` additional info

- You may create as many `services` as You want but service names **MUST be unique**
- You may create new types but they **MUST exist in** `type_banned` **and in** `type_match_banned`
- `Port` **MUST be unique** between ports and proxyports
- `Proxyport` **MUST be unique** between proxyports and ports
- You can't edit `port` and / or `proxyport` after that service has been started. If You need to change them, You may restart proxy or edit the name too: the current service will be closed and a new one will be created with the new `port` and / or `proxyport` (and new name, You may want to change back again the name only)

Another example of `services.json` while using a custom type 
```
{
	"services": {
		"AnotherExample": {
			"type": "customtype",
			"banned": [],
			"match_banned": [],
			"port": 9000,
			"proxyport": 50000
        },
        "CryptoBros": {
			"type": "crypto",
			"banned": [],
			"match_banned": [],
			"port": 10000,
			"proxyport": 50100
        },
        "AnotherExampleTheRevenge": {
			"type": "customtype",
			"banned": [],
			"match_banned": [],
			"port": 9050,
			"proxyport": 50200
        }
},
	"gen_banned": [],
	"gen_match_banned": [],
	"type_banned": {
		"crypto": [],
		"customtype": []
	},
	"type_match_banned": {
		"crypto": [],
		"customtype": []
	}
}
```
## Demo

![](/http/multiprocess_proxy/demo/demo.gif)
