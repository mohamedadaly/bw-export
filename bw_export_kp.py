#!/usr/bin/python

from __future__ import print_function
import base64
import commands
import json
import sys
import uuid
import xmltodict

"""
Exports a Bitwraden database into an XML file conforming to KeePass 2 XML Format.
The advantage of the XML format, is that it supports importing custom fields from
Bitwarden into their own custom fields in KeePass 2, which is not currently supported
in the Bitwarden CSV import function.

Usage: 

# 1. log into bw
$ bw login

# 2. export xml
$ python bw_export_kp.py > passwords.xml

# Or export a json file from bitwarden and then export xml using
$ python bw_export_kp.py <path/to/json/file> > passwords.xml

# 3. import the passwords.xml file into KeePass 2 (or other KeePass clones that 
# support importing KeePass2 XML formats)

# 4. delete passwords.xml

References:
- Bitwarden CLI: https://help.bitwarden.com/article/cli/
- KeePass 2 XML: https://github.com/keepassxreboot/keepassxc-specs/blob/master/kdbx-xml/rfc.txt
"""

def get_uuid(name):
    """
    Computes the UUID of the given string as required by KeePass XML standard
    https://github.com/keepassxreboot/keepassxc-specs/blob/master/kdbx-xml/rfc.txt
    """
    name = name.encode('ascii', 'ignore')
    uid = uuid.uuid5(uuid.NAMESPACE_DNS, name)
    return base64.b64encode(uid.bytes)                                       


def get_folder(f):
    """
    Returns a dict of the input folder JSON structure returned by Bitwarden.
    """
    return dict(UUID=get_uuid(f['name']),
                Name=f['name'])
                

def get_protected_value(v):
    """
    Returns a Value element that is "memory protected" in KeePass
    (useful for Passwords and sensitive custom fields/strings).
    """
    return {'#text': v, '@ProtectInMemory': 'True'}


def get_fields(subitem, protected=[], prefix=''):
    """
    Returns the components of subitem as a fields array,
    protecting the items in protected list
    """
    fields = []

    for k, v in subitem.iteritems():
        # check if it's protected
        if k in protected: 
            v = get_protected_value(v)

        # add prefix
        k = prefix + k
        fields.append(dict(Key=k, Value=v))

    return fields

def get_entry(e):
    """
    Returns a dict of the input entry (item from Bitwarden)
    Parses the title, username, password, urls, notes, and custom fields.
    """
    # Parse custom fields, protecting as necessary
    fields = []
    if 'fields' in e:
        for f in e['fields']:
            if f['name'] is not None:
                # get value
                value = f['value']
                # if protected?
                if f['type'] == 1:
                    value = get_protected_value(value)
                # put together
                fields.append(dict(Key=f['name'], Value=value))
        
    # default values
    urls = ''
    username, password = '', ''
    notes = e['notes'] if e['notes'] is not None else ''

    # read username, password, and url if a login item
    if 'login' in e:
        login = e['login']
        if 'uris' in login:
            urls = [u['uri'] for u in login['uris']]
            urls = ','.join(urls)
            
        # get username and password
        username = login['username'] 
        password = login['password'] 

        # add totop to fields as protected
        fields.append(dict(Key='totp', 
                           Value=get_protected_value(login['totp'])))

    # Parse Card items
    if 'card' in e:
        # Make number a protected field
        fields.extend(get_fields(e['card'], protected=['number']))

    # Parse Identity items
    if 'identity' in e:
        fields.extend(get_fields(e['identity']))

    # Parse Password History
    if 'passwordHistory' in e:
        hists = e['passwordHistory']
        # loop on the list
        for i, hist in enumerate(hists):
            prefix = 'Old #%d ' % (i + 1)
            fields.extend(get_fields(hist, 
                                     protected=['password'],
                                     prefix=prefix))
            # # Add the password
            # key = prefix
            # val = get_protected_value(hist['password'])
            # fields.append(dict(Key=key, Value=val))

            # # Add the date
            # key = prefix + ' Date'
            # val = hist['lastUsedDate']
            # fields.append(dict(Key=key, Value=val))
        
    # Check it's not None
    username = username or ''
    password = password or ''

    # assemble the entry into a dict with a UUID
    entry = dict(UUID=get_uuid(e['name']),
                String=[dict(Key='Title', Value=e['name']),
                        dict(Key='UserName', Value=username),
                        dict(Key='Password', Value=get_protected_value(password)),
                        dict(Key='URL', Value=urls),
                        dict(Key='Notes', Value=notes)
                       ] + fields)
                
    return entry


def get_cmd_output(cmd):
    """
    Returns the output of the given command
    """
    status, output = commands.getstatusoutput(cmd)
    if status != 0:
        print("Error running command: '%s'" % cmd)
        sys.exit(1)

    return output


def get_bw_data(file_name=None):
    """
    Gets the folders and items from Bitwarden CLI
    """
    if file_name is None:
        # get folders
        cmd = 'bw list folders'
        folders = json.loads(get_cmd_output(cmd))

        # get items
        cmd = 'bw list items'
        items = json.loads(get_cmd_output(cmd))

    else:
        # load the contents of the json file
        data = json.load(open(file_name, 'r'))
        folders = data['folders']
        items = data['items']

        # Add null folder if not there
        nullFolder = [f for f in folders if f['id'] is None]
        if len(nullFolder) == 0:
            folders.append({u'id': None, u'name': u'Root'})
        # print(folders)

    return folders, items


def main():
    """
    Main function
    """
    # The name of the json file
    file_name = None
    if len(sys.argv) > 1: file_name = sys.argv[1]

    # get data from bw
    bw_folders, bw_items = get_bw_data(file_name)
    
    # parse all entries
    entries = [get_entry(e) for e in bw_items]
    
    # Meta element
    meta = dict()
    
    # loop over folders
    # bw_folders = d['folders']
    folders = []
    root_entries = []
    for f in bw_folders:
        # parse the folder
        folder = get_folder(f)
        folder_id = f['id']
        
        # loop on entries in this folder
        folder_entries = []
        for entry, item in zip(entries, bw_items):
            if item['folderId'] == folder_id:
                folder_entries.append(entry)
        
        # NoFolder (with None id)
        if folder_id is None:
            root_entries = folder_entries
        # Normal folder
        else:
            if len(folder_entries) > 0:
                folder['Entry'] = folder_entries 
    
            # add to output folder
            folders.append(folder)
    
    # Root group
    root_group = get_folder(dict(name='Root'))
    root_group['Group'] = folders

    # add items to root folder
    if len(root_entries) > 0:
        root_group['Entry'] = root_entries
    
    # Root element
    root=dict(Group=root_group)
    
    # xml document contents
    xml = dict(KeePassFile=dict(Meta=meta, Root=root))

    # write XML document to stdout
    print(xmltodict.unparse(xml, pretty=True))


if __name__ == "__main__":
    main()
