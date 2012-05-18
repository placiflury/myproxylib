#!/usr/bin/env python 

""" My proxy client. Demo on how to use myproxylib.py """
# Copyright (c) 2012, SWITCH - Serving Swiss Universities
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the SWITCH nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys

from myproxylib import MyProxy, UserCredential

__version__ = '0.1'

class MyProxyClient(object):

    def __init__(self, host, port=7512, certfile=None, keyfile=None, debug=False):
        """ 
            host -- hostname of MyProxy server
            port -- port on which sever listens
            certfile - file (path) wherefrom to read (user) certificate. 
                       If not set, it will be defaulted to $HOME/.globus/usercert.pem
            keyfile - file (path) wherefrom to read (user) key. If not set
                        it will be defaulted to $HOME/.globus/userkey.pem   

            Notice, certfile and keyfile must be PEM encoded 
        """
        self.debug = debug
        self._usercert = None
        self._userkey = None
        self._keyfile = keyfile # used by SSL Context
        self._certfile = certfile

        self._my_proxy = MyProxy(host, port)

    def set_certfile(self, certfile):
        """ setting certfile for communication with MyProxy server"""
        self._certfile = certfile

    def set_keyfile(self, keyfile):
        """ setting keyfile for communication with MyProxy server"""
        self._keyfile = keyfile
        
    def set_key_size(self, bits):
        """ Sets key size of generated proxy """
        self._my_proxy.set_key_size(bits)
        print "key size", self._my_proxy.get_key_size()

    def set_proxy_type(self, px_type, px_policy):
        """ Sest type of proxy to upload """
        self._my_proxy.set_proxy_type(px_type)
        self._my_proxy.set_proxy_policy(px_policy)
    
    def myproxy_logon(self, username, passphrase, outfile):
        """
        Function to retrieve a proxy credential from a MyProxy server
        
        Exceptions:  MyProxyError, MyProxyInputError, MyProxySSLError
        """

        self._my_proxy.init_context(self._certfile, self._keyfile)

        proxy_credential = self._my_proxy.get(username, passphrase)

        if self.debug:
            print 'Storing proxy in:', outfile

        proxy_credential.store_proxy(outfile)
        

    def myproxy_init(self, username, myproxy_passphrase, 
            keyfile, certfile, lifetime = None):
        """ downsized myproxy_init 
            username -- name used on MyProxy server for storing credential
            myproxy_passphrase -- passphrase for credentials on MyProxy server
            keyfile -- user local key file
            certfile -- user local certificate file
            lifetime -- sets max lifetime allowed for retrieved proxy credentials (in secs).
                        If lifetime not set, we'll set it to a libraries default value
        """
         
        key_passphrase = getpass.getpass(prompt = "Grid passphrase:")
        user_credential = UserCredential(keyfile, certfile, key_passphrase)
        self._my_proxy.init_context(self._certfile, self._keyfile, key_passphrase)
        proxy_credential = self._my_proxy.put(user_credential, username, myproxy_passphrase, lifetime)



if __name__ == '__main__':
    import optparse
    import getpass

    MIN_PASS_PHRASE = 7 # minimal length of myproxy passphrase

    if os.environ.has_key('MYPROXY_SERVER'):
        MYPROXY_SERVER = os.environ['MYPROXY_SERVER']
    else:
        MYPROXY_SERVER = 'apollo.switch.ch' 

    usage = "usage: %prog [options] get|put \n\nDo %prog -h for more help."

    parser = optparse.OptionParser(usage = usage, version = "%prog " + __version__)
    parser.add_option("-l", "--username", dest = "username", default = os.environ['USER'],
                    help="The username with which the credential is stored on the MyProxy server")
    parser.add_option("-d", "--debug", action = 'store_true', default = False,
                    help = "Enhance verbosity for debugging purposes")

    parser.add_option("", "--limited",  action = 'store_true',  
                    default = False,
                    help = "Creates a limited globus proxy (policy). (default=%default).")
    parser.add_option("", "--old",  action = 'store_const', const = 'old', dest = 'px_type',
                    help = "Creates a legacy globus proxy.")
    parser.add_option("", "--rfc",  action = 'store_const',  const = 'rfc', dest = 'px_type', 
                    default = 'rfc',
                    help = "Creates a RFC3820 compliant proxy (default)." )

    parser.add_option("", "--bits", dest = "bits", default = 1024, type ='int',
                    help="Number of bits in key (512, 1024, 2048, default=%default) " + \
                "of signing proxy. All other key sizes defined by myproxy server. ")
    parser.add_option("", "--cert", dest = "certfile",
                    default = '%s/.globus/usercert.pem' % (os.environ['HOME']), 
                    help = "Location of user certificate(default = %default).")
    parser.add_option("", "--key", dest = "keyfile",
                    default = '%s/.globus/userkey.pem' % (os.environ['HOME']), 
                    help = "Location of user certificate(default = %default).")

    parser.add_option("", "--out", dest = "outfile",
                    default = '/tmp/x509up_u%s' % (os.getuid()), 
                    help = "Filenname under which user proxy certificate gets stored (default = %default).")

    (options, args) = parser.parse_args()

    if not args:
        parser.error("incorrect number of arguments")

    if args[0] not in ['put', 'get']:
        parser.error("wrong argument")
    
    username = options.username

    if options.debug:
        print 'Invoked with following parameters:'
        print 'options:', options
        print 'arguments:', args


        
    try:
        mp = MyProxyClient(host = MYPROXY_SERVER, debug = options.debug)
        if args[0] == 'get':
            passphrase = getpass.getpass(prompt="MyProxy passphrase:")
            mp.myproxy_logon(username, passphrase, options.outfile)
            if options.outfile:
                print "A proxy has been received for user %s in %s." % (username, options.outfile)
            else:
                print "A proxy has been received for user %s" % (username)
        elif args[0] == 'put':
            passphrase = getpass.getpass(prompt="MyProxy passphrase:")
            if len(passphrase) < MIN_PASS_PHRASE:
                print 'Error Passphrase must contain at least %d characters' % MIN_PASS_PHRASE
                sys.exit(-1)
            mp.set_certfile(options.certfile)
            mp.set_keyfile(options.keyfile)
            mp.set_key_size(options.bits)
            policy = 'normal'
            if options.limited:
                policy = 'limited'
            mp.set_proxy_type(options.px_type, policy)
            mp.myproxy_init(username, passphrase, options.keyfile, options.certfile)
            print 'Credential for delegation was succesfully up-loaded'
    except Exception, e:
        print "Error:", e
