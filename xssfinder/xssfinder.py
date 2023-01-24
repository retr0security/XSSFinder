#!/usr/bin/env python
# -*- coding: utf-8 -*-

__Name__ = "XSSFinder"
__description__ = "XSSFinder itss a updated version of scancss"
__author__ = "Rootkit Security"
__copyright__ = "Copyright 2023."
__license__ = "GNU v.20"
__version__ = "v1"





# Import Modules.
import argparse

from aiohttp import HttpVersion
from core import *
from random import randint
from Log import *
from helper import *
from crawler import *


# Style class
class Style:
    reset = '\033[0m'
    bold = '\033[01m'
    underline = '\033[04m'
    red = '\033[31m'
    blue = '\033[34m'
    cyan = '\033[36m'
    lightgrey = '\033[37m'
    darkgrey = '\033[90m'
    yellow = '\033[93m'


epilog = f"""
_  ___  ______ _____\_   _____/|__| ____    __| _/___________ 
\  \/  / /  ___//  ___/|    __)  |  |/    \  / __ |/ __ \_  __ \
 >    <  \___ \ \___ \ |     \   |  |   |  \/ /_/ \  ___/|  | \/
/__/\_ \/____  >____  >\___  /   |__|___|  /\____ |\___  >__|   
      \/     \/     \/     \/            \/      \/    \/       
__________ ________   _______________________  __.______________
\______   \\_____  \  \_____  \__    ___/    |/ _|   \__    ___/
 |       _/ /   |   \  /   |   \|    |  |      < |   | |    |   
 |    |   \/    |    \/    |    \    |  |    |  \|   | |    |   
 |____|_  /\_______  /\_______  /____|  |____|__ \___| |____|   
        \/         \/         \/                \/           
"""


def check(getopt):
    payload = int(getopt.payload_level)
    if payload > 6 and getopt.payload is None:
        Log.info("Do you want use custom payload (Y/n)?")
        answer = input("> {W}")
        if answer.lower().strip() == "y":
            Log.info("Write the XSS payload below")
            payload = input("> {W}")
        else:
            payload = core.generate(randint(1, 6))

    else:
        payload = core.generate(payload)

    return payload if getopt.payload is None else getopt.payload


def start():
    parse = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                    usage="scancss -u <target> [options]", epilog=epilog, add_help=False)

    pos_opt = parse.add_argument_group("Options")
    pos_opt.add_argument("--help", action="store_true",
                         default=False, help="Show usage and help parameters")
    pos_opt.add_argument(
        "-u", metavar="", help="Target url (e.g. http://example.com)")
    pos_opt.add_argument("--depth", metavar="",
                         help="Depth web page to crawl. Default: 2", default=2)
    pos_opt.add_argument("--payload-level", metavar="",
                         help="Level for payload Generator, 7 for custom payload. {1...6}. Default: 6", default=6)
    pos_opt.add_argument("--payload", metavar="",
                         help="Load custom payload directly (e.g. <script>alert(2005)</script>)", default=None)
    pos_opt.add_argument("--method", metavar="",
                         help="Method setting(s): \n\t0: GET\n\t1: POST\n\t2: GET and POST (default)", default=2, type=int)
    pos_opt.add_argument("--user-agent", metavar="",
                         help="Request user agent (e.g. Chrome/2.1.1/...)", default=agent)
    pos_opt.add_argument("--single", metavar="",
                         help="Single scan. No crawling just one address")
    pos_opt.add_argument("--proxy", default=None, metavar="",
                         help="Set proxy (e.g. {'https':'https://10.10.1.10:1080'})")
    pos_opt.add_argument("--about", action="store_true",
                         help="Print information about scancss tool")
    pos_opt.add_argument(
        "--cookie", help="Set cookie (e.g {'ID':'1094200543'})", default='''{"ID":"1094200543"}''', metavar="")

    getopt = parse.parse_args()
    print(logo)
    Log.info(f"{Style.bold}{Style.blue}--scancss{Style.reset}{Style.cyan}")
    if getopt.u:
        core.main(getopt.u, getopt.proxy, getopt.user_agent,
                  check(getopt), getopt.cookie, getopt.method)

        crawler.crawl(getopt.u, int(getopt.depth), getopt.proxy,
                      getopt.user_agent, check(getopt), getopt.method, getopt.cookie)

    elif getopt.single:
        core.main(getopt.single, getopt.proxy, getopt.user_agent,
                  check(getopt), getopt.cookie, getopt.method)

    elif getopt.about:
        print(f"""
***************
This Tool Made of Educational and legal purpose Only,
Please Don't Use it for Any Bad or Illegal Purpose.
****************
{epilog}""")
    else:
        parse.print_help()


if __name__ == "__main__":
 start()

 # create a function to send a encoded HTTP request
def send_request(url, payload):
    # create a new session
    session = requests.Session()
    session = HttpVersion(encoded_payload)
    session.send_request(url, payload, "IP")
    # create a new header
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    ## Create Encoded XSS Payload
    # encode the payload
    encoded_payload = urllib.parse.quote(payload)
    encoded_payload = encoded_payload.replace("%3C", "<")
    encoded_payload = encoded_payload.replace("%3E", ">")
    encoded_payload = payload.send_HTTP(list, "targets.txt")
    # send the request
    response = session.post(url, data=encoded_payload, headers=headers)
    # return the response
    return response
    response = headers.encode("utf-8")
    response = session.send_request(url, payload, "IP")
    response = "IP"
    response = "80"
    os_opt.add_argument("--proxy", help="server proxy", default="IP")
    ## Create a function to check if the payload is reflected
def check_reflected(response, payload):
    def check_reflected(response, payload):
        # check if the payload is in the response
        if payload in response.text:
            # return true if it is
            return True
        else:
            # return false if it is not
            return False
            check_reflected = HTTP.Request("IP", "80")
            check_reflected = (True)
            ## when the payload is reflected, print the response
            if check_reflected(response, payload):
                check_reflected(headers, payload)
                print(response.text)
                print("The payload was reflected!")
                



