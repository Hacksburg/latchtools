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
import smtplib
from datetime import datetime,date
from email.mime.text import MIMEText


filename = "latchburg.log"
date_format = "%Y-%m-%d"

# This is the regex for the logfile. Breaking it down:
# (\d{4}-\d{2}-\d{2})) matches the date
# (\d{2}:\d{2}:\d{2}) matches the time (we leave the milliseconds out of the capture group because we don't need that resolution)
# ([AU]) matches the first character in "Allowed" or "Unauthorized" in order to see whether entry was allowed or denied.
# Since card numbers of denied persons are logged, and that may contain sensitive info, it's important that that not go out in an email.
# (\S+$) matches all characters after the last whitespace until the end, where it captures the user name.
pattern = "(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}),\d{3} ([AU]).*\s(\S+$)"

# SMTP info. All fields required. SMTP over TLS on port 587 only; if you want it differently, code it yourself :P
smtp_user = ""
smtp_pass = ""
smtp_server = ""
smtp_sender = ""
# this can be one email address or a list of email addresses
smtp_recipients = ""

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
        
    # send out our CSV, unless we don't have all email creds or 'noemail' is in the program args, in which case print them
    if smtp_server and smtp_user and smtp_pass and smtp_sender and smtp_recipients and not ("noemail" in args):
        message = MIMEText(result)
        message['Subject'] = "Latchscan results for " + target_date.isoformat()
        message['From'] = smtp_sender
        message['To'] = smtp_recipients
        mail = smtplib.SMTP()
        try:
            mail.connect(smtp_server,587)
            mail.starttls()
            mail.login(smtp_user,smtp_pass)
            mail.send_message(message)
        except smtplib.SMTPException as e:
            print("SMTP error: " + str(e), file=sys.stderr)
        finally:
            mail.quit()
    else:
        print(result)
        

if (len(sys.argv) >= 2):
    main(sys.argv[1:])
else:
    main()
