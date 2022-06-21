import os
import mailbox
import re
import time
import sys
import xml.dom.minidom
import HTMLParser
import argparse
import hangouts
from email.utils import parsedate, parsedate_tz, mktime_tz
import quopri

def extract_date_mbox(email):
    date = email.get('Date')
    return parsedate(date)

def filename_sanitize(input):
    return re.sub("([^a-zA-Z0-9._-])", "_", input)

def make_filename_json(member_array, name, email):
    outstr = ''
    for i in member_array:
        if member_array[i] not in (name, email):
            if outstr != '':
                outstr += "_"
            outstr += member_array[i];
    #Need to limit total filename size to 255
    return outstr[:250] + ".txt"

def msg_to_logline_json(message):
    return "%s <%s> %s\n" % (message['datetime'],  message['sender'], message['message'])

def write_to_file(filename, lines):
    '''Write a set of lines to a specified file.

    @param filename: path to file
    @type filename: string
    @param lines: array of log lines (strings) to write
    @type lines: [string, string, ...]

    '''
    with open(filename, "a") as myfile:
            myfile.write("".join(lines))

def parse_mailbox(mailbox_path, my_name, my_email, timestamp_format, use_mbox):
    if not use_mbox:
        mailbox_path = os.path.join(mailbox_path,"")
        if not os.path.isdir(mailbox_path + 'new'):
            os.mkdir(mailbox_path + 'new')
        if not os.path.isdir(mailbox_path + 'tmp'):
            os.mkdir(mailbox_path + 'tmp')

    if use_mbox:
        mbox = mailbox.mbox(mailbox_path)
    else:
        mbox = mailbox.Maildir(mailbox_path, None)
    sorted_mails = sorted(mbox, key=extract_date_mbox)

    # Sometimes thunderbird will produce mbox files with duplicate messages.
    # Keep track of all seen Message-ID's to prevent writing out duplicate
    # lines to the logs.
    seen_ids = set()

    for message in sorted_mails:

        messageobj = []

        # Very rarely (happened to me with only 1 message out of 25,000),
        # Thunderbird/GMail will produce a malformed message with a payload,
        # but no metadata. Just skip these, but print a warning so the user
        # can ensure that this is not happening too often.
        if len(message.keys()) == 0:
            print("Warning: Skipping malformed message")
            continue

        # Skip duplicates
        if message['Message-ID'] in seen_ids:
            continue
        seen_ids.add(message['Message-ID'])

        name = get_chat_name(message, my_name, my_email)

        payload = message.get_payload()
        if type(payload) is str:
            # We're in one of the new hybrid-style single-use messages

            # Some (but not all) of these messages use quoted-printable
            # encoding (which uses = as an escape character).
            # The remainder are encoded with 7bit ASCII, which must not
            # be decoded, because treating = as an escape causes havoc.
            if message['Content-Transfer-Encoding'] == 'quoted-printable':
                payload = quopri.decodestring(payload)
                payload = payload.decode('utf-8')
            payload = payload.strip()
            rawtimestr = message.get('Date')
            if not rawtimestr:
                print('Found broken message with no Date field from ' + message['From'])
                continue
            timestamp = time.strftime(timestamp_format, parsedate(rawtimestr))

            pars = HTMLParser.HTMLParser()
            outline = "%s <%s> %s\n" % (timestamp, from_name, pars.unescape(payload))
            messageobj.append(outline.encode('utf-8'))
        else:
            # We're in an old Google Talk Jabber conversation message

            payload = payload[0].as_string()

            # Seemingly all of these messages use quoted-printable encoding,
            # even though 'Content-Transfer-Encoding' is never set.
            payload = quopri.decodestring(payload)
            payload = payload.decode('utf-8', errors='replace')
            # The emails have a couple of chaff lines before the XML starts
            payload = re.sub(r'^[^<]*<', "<", payload)

            try:
                chatxml = xml.dom.minidom.parseString(payload.encode('utf-8'))
            except:
                # this may break on things like URLs with '=' in messages
                # can try replacing them with encoding (e.g., %3D)
                print(payload.encode('utf-8'))
                sys.exit("Error parsing xml")

            # for messagexml in chatxml.getElementsByTagName("cli:message"):
            for messagexml in chatxml.getElementsByTagNameNS("*", "message"):
                speaker = messagexml.getAttribute("from")
                rawtimestr = messagexml.getElementsByTagName("time")[0].getAttribute("ms")
                timefloat = float(rawtimestr[:-3] + "." + rawtimestr[-3:])
                timestamp = time.strftime(timestamp_format,time.localtime(timefloat))
                try:
                    # content = messagexml.getElementsByTagName("cli:body")[0].firstChild.data
                    content = messagexml.getElementsByTagNameNS("*", "body")[0].firstChild.data
                except AttributeError:
                    # No 'data' element means that it's an empty message
                    content = ""
                except IndexError:
                    # No "cli:body" elements means that it's a non-message event,
                    # like a time-gap or user-unavailable message
                    continue
                outline = "%s <%s> %s\n" % (timestamp, speaker, content)
                messageobj.append(outline.encode('utf-8'))

        # convert message date field to a local time and separate chats with this info
        chat_date = '???'
        if message['Date']:
            chat_date = time.strftime(timestamp_format, time.localtime(mktime_tz(parsedate_tz(message['Date']))))
        elif message['Received']:
            chat_date = message['Received'].split(';')[-1].strip()
        message_header = '\nChat dated ' + chat_date
        message_header += '\n-------------------------------------------------------\n'
        write_to_file("%s.txt" % filename_sanitize(name)[:250], message_header)
        write_to_file("%s.txt" % filename_sanitize(name)[:250], messageobj)


def get_chat_name(message, my_name, my_email):
    """ Find the best match for the name of other chat participant."""

    # Takeout mbox does not always have subject field!
    name = None
    if message['subject']:
        return re.sub("Chat with ", "", message['subject'])

    if message['From']:
        return re.sub(" <[^>]*>", "", message.get('From'))

    if message['To']:
        to_name = re.sub(" <[^>]*>", "", message.get('To'))
        if to_name != my_name and to_name != my_email:
            return to_name

    print("Unknown chat name!")
    return "Unknown"


def parse_json(json_path, name, email, timestamp_format):
    with open(json_path, "r") as myfile:
        mydata=myfile.read()

    conversations = hangouts.hangoutsToArray(mydata, timestamp_format)

    print("JSON file first pass completed.  Writing to logfiles...")

    for conversation in conversations:
        filename = filename_sanitize(make_filename_json(conversation['members'],
                                                        name, email))
        messageobj = []
        for message in conversation['messages']:
            messageobj.append(msg_to_logline_json(message).encode("UTF-8"))

        message_header = '\nHangouts'
        message_header += '\n-------------------------------------------------------\n'
        write_to_file(filename, message_header)
        write_to_file(filename, messageobj)

parser = argparse.ArgumentParser(prog="gtalk_export")
parser.add_argument("-p", "--mailbox-path",
                    required=False,
                    default=None,
                    help="The location of the IMAP Maildir or mbox to parse")
parser.add_argument("-j", "--json-path",
                    required=False,
                    default=None,
                    help="The location of the Takeouts JSON to parse")
parser.add_argument("-n", "--name",
                    required=True,
                    help="The chat participant name whose files are being parsed")
parser.add_argument("-e", "--email",
                    required=True,
                    help="The chat participant email whose files are being parsed")
parser.add_argument("-t", "--timestamp-format",
                    required=False,
                    default='%Y-%m-%d %H:%M:%S',
                    help="Timestamp format to display in output logs")
parser.add_argument("-m", "--mbox",
                    action='store_true',
                    help="Use mbox instead of Maildir")

args = parser.parse_args()

if args.mailbox_path is None and args.json_path is None:
    sys.exit("No mbox or JSON provided -- nothing to do!")

if args.mailbox_path:
    print("Processing mailbox at %s" % args.mailbox_path)
    parse_mailbox(args.mailbox_path, args.name, args.email, args.timestamp_format, args.mbox)
    print("Finished processing mailbox")

if args.json_path:
    print("Processing json file at %s" % args.json_path)
    parse_json(args.json_path, args.name, args.email, args.timestamp_format)
    print("Finished processing json file")

print("GTalk/Hangouts export completed!")
