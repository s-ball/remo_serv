#  Copyright (c) 2020 SBA- MIT License

import urllib.request
import time


SERVER = 'http://localhost:8080'


def run():
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor)
    r = opener.open(SERVER + '/')
    print(r.code)
    print(r.headers, end='')
    print(r.read())
    r = opener.open(SERVER + '/')
    print(r.code)
    print(r.headers, end='')
    print(r.read())
    time.sleep(30)
    r = opener.open(SERVER + '/')
    print(r.code)
    print(r.headers, end='')
    print(r.read())


if __name__ == '__main__':
    run()