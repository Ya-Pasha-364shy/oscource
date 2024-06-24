import pexpect
import os

HTTP_RESPONSE = '<!DOCTYPE html>\n<html><body><h1>Hello from JOS!</h1></body></html>'
UDP_HELLO = 'HELLO'


def test_arp():
    template: str = 'test arp - {verdict}'
    result: str = pexpect.run('sudo arping -c 1 172.16.0.2').decode('utf-8')
    if '1 packets received' in result:
        print(template.format(verdict='OK'))
    else:
        print(template.format(verdict='FAIL'))


def test_ping():
    template: str = 'test ping - {verdict}'
    result: str = pexpect.run('ping -c 3 172.16.0.2').decode('utf-8')
    if '3 packets transmitted, 3 received' in result:
        print(template.format(verdict='OK'))
    else:
        print(template.format(verdict='FAIL'))


def test_udp():
    result: str = pexpect.run('./udp_test').decode('utf-8')
    template: str = 'test udp - {verdict}'
    if result == UDP_HELLO:
        print(template.format(verdict='OK'))
    else:
        print(template.format(verdict='FAIL'))


def test_http_response():
    try:
        os.remove('index.html')
        os.remove('wget-log')
    except FileNotFoundError:
        pass
    template: str = 'test http response - {verdict}'
    pexpect.run('wget 172.16.0.2')
    try:
        with open('index.html') as f:
            content: str = f.read()
            if content == HTTP_RESPONSE:
                print(template.format(verdict='OK'))
            else:
                print(template.format(verdict='FAIL'))
    except:
        print(template.format(verdict='FAIL'))
    try:
        os.remove('index.html')
        os.remove('wget-log')
    except FileNotFoundError:
        pass


def main():
    test_arp()
    test_ping()
    test_udp()
    test_http_response()


if __name__ == '__main__':
    main()