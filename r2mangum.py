import sys
import json
import r2pipe
from pprint import pprint

__author__ = 'Hapsida @securisec'
__version__ = '0.1.0'

if sys.version_info.major == 2:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen

# Will change this once I get a valid mangnumdb key
key = 'f344dc86-7796-499f-be38-ec39a5414289'

r2 = r2pipe.open()
get_current_dis = r2.cmdj('pdj 1')[0]

if not get_current_dis.get('ptr'):
    print('Cannot get ptr from current offset')
else:
    offset = hex(get_current_dis.get('ptr'))

    r = urlopen(
        'https://www.magnumdb.com/api.aspx?q={offset}&key={key}'.format(
            offset=offset, key=key
        )
    )

    data = json.loads(r.read())
    if data['TotalHits'] == 0:
        print('No matches found')
    elif data['TotalHits'] == 1:
        flag = data['Items'][0]['DisplayTitle']
        r2.cmd('f mdb.{flag} @{offset}'.format(flag=flag, offset=offset))
        print('Renamed {offset} to {flag}'.format(offset=offset, flag=flag))
    else:
        print('Too many matches')
        pprint(data)
