#!/bin/python

# Latchscan, a Latchburg log scanner
# Copyright (C) 2016 Andrew Mike

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import re
from datetime import datetime,date


filename = "latchburg.log"
date_format = "%Y-%m-%d"
# This is the regex for the logfile. Breaking it down:
# (\d{4}-\d{2}-\d{2})) matches the date
# (\d{2}:\d{2}:\d{2}) matches the time (we leave the milliseconds out of the capture group because we don't need that resolution)
# ([AU]) matches the first character in "Allowed" or "Unauthorized" in order to see whether entry was allowed or denied.
# Since card numbers of denied persons are logged, and that may contain sensitive info, it's important that that not go out in an email.
# .*(\s\S+$) matches all remaining characters until the end, where it captures the user name.
pattern = "(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}),\d{3} ([AU]).*(\s\S+$)"

def main(args=[]):
    # Can we convert the first argument passed in into a date? If not, use today's date.
    try:
        target_date = datetime.strptime(args[0], date_format)
    except ValueError:
        print("No date found, using today's.", file=sys.stderr)
        target_date = date.today()
    
    # compile the regex for the search and put up a CSV header.
    searcher = re.compile(pattern)
    result = "Date,Time,User\n"
    
    # If we can open the file, read every line and scrape our data.
    try:
        with open(filename,'r') as f:
            for line in f:
                hit = searcher.search(line)
                # If we get a hit, and if the date is today's, start grabbing things
                if hit and (datetime.strptime(hit.group(1), date_format) == target_date):
                    result += hit.group(1) + "," + hit.group(2) + ","
                    # If the user was authorized, print their name. If not, print [unauthorized] instead of their card data.
                    if hit.group(3) == "A":
                         result += hit.group(4) + "\n"
                    else:
                        result += "[unauthorized]\n"
    except IOError:
        print("Cannot open file " + filename + "due to an I/O error.", file=sys.stderr)
    except NameError:
        print("Unable to find file " + filename + ". Check your path and try again.", file=sys.stderr)
        
    # print our CSV.
    # TODO: replace with emailing this out? Or pipe to sendmail?
    print(result)

if (len(sys.argv) >= 2):
    main(sys.argv[1:])
else:
    main()
