#!/usr/bin/env python3

from html.parser import HTMLParser
from enum import Enum

class State(Enum):
    NOWHERE = 0
    COMPANY = 1
    AFTER_COMPANY = 2
    PNPID = 3
    AFTER_PNPID = 4
    DATE = 5

class PNPTableParser(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)
        self.state = State.NOWHERE
        self.data = ""
        self.pnpid = None
        self.company = None
        self.table = []

    def handle_starttag(self, tag, attrs):

        if tag == "td":
            if self.state == State.NOWHERE:
                self.state = State.COMPANY
            elif self.state == State.AFTER_COMPANY:
                self.state = State.PNPID
            elif self.state == State.AFTER_PNPID:
                self.state = State.DATE
            else:
                raise ValueError

            self.data = ""

    def handle_endtag(self, tag):

        if tag == "td":
            if self.state == State.COMPANY:
                self.company = ' '.join(self.data.strip().split())
                self.state = State.AFTER_COMPANY
            elif self.state == State.PNPID:
                self.pnpid = self.data.strip()
                self.state = State.AFTER_PNPID
                self.table.append((self.pnpid, self.company))
            elif self.state == State.DATE:
                self.state = State.NOWHERE
            else:
                raise ValueError

    def handle_data(self, data):
        self.data += data

def read_table(a):

    parser = PNPTableParser()

    for line in a:
        parser.feed(line)

    parser.close()
    parser.table.sort()

    for pnpid, company in parser.table:
        print("\nacpi:{0}*:\n ID_VENDOR_FROM_DATABASE={1}".format(pnpid, company))

a = open("acpi_id_registry.html")
b = open("pnp_id_registry.html")

print('# This file is part of systemd.\n'
      '#\n'
      '# Data imported from:\n'
      '#     https://uefi.org/uefi-pnp-export\n'
      '#     https://uefi.org/uefi-acpi-export')

read_table(a)
read_table(b)
