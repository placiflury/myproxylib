#!/usr/bin/env python

""" Reads pem-encoded certs from file and 
    prints subject-issuer pair for each certificate.
    Can be used to verify completenes of certificate chains.

"""
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

from M2Crypto import X509 

__version__ = '0.1.0'

def certs_from_file(filename):
    """ Extracts certificates from (pem-encoded)
        from file. 
        
        Returns -- string list of X509 cert objects.
                as input for X509.load_cert_string method.
    """
    START = '-----BEGIN CERTIFICATE-----'
    END = '-----END CERTIFICATE-----'
    
    cert_list = list()
    cert_str  = ''
    read_flag = False

    with open(filename,'r') as f:
        for line in f:
            if END in line:
                read_flag = False
                cert_str += line
                x509 = X509.load_cert_string(cert_str, X509.FORMAT_PEM)
                cert_list.append(x509)
                cert_str = ''

            if START in line:
                read_flag = True
            if read_flag:
                cert_str += line
        
    return cert_list

def verify_chain(certificates, verbose = True):
    """
    Verification of a certificate chain. 
    
    input:
    certificates -- list of certificate objects. The
                    order matters (CA certificate must be last
                    if interated) 

    verbose -- if set to true, the subject and issuer will 
              be printed for each check

    returns: True if ok, False if chain wrong or incomplete

    """
    crt = None
    cnt = 0
    for issuer in certificates:
        issuer_dn = issuer.get_subject().as_text()
        if crt: 
            crt_issuer_dn = crt.get_issuer().as_text()
            if crt_issuer_dn != issuer_dn:
                if verbose:
                    print 'Error, chain broken at certificate number %d' % cnt
                    print 'Details:'
                    print 'Cert subject:', crt.get_subject().as_text()
                    print 'Cert issuer: ', crt.get_issuer().as_text() 
                    print 'Issuer DN: ' , issuer_dn

                return False

            elif verbose:
                print '-' * 10, ' ', cnt, ' ', '-'*10 
                print 'Cert subject:', crt.get_subject().as_text()
                print 'Cert issuer: ', crt.get_issuer().as_text() 
                print 'Issuer DN: ' , issuer_dn
                
        if issuer.check_ca() != 0  and \
            (issuer_dn == issuer.get_issuer().as_text()):

            if verbose:
                print '\n ### Found Root CA ### '
                print 'subject:', issuer_dn
                print 'issuer: ', issuer.get_issuer().as_text() 
            return True

        cnt += 1
        crt = issuer

    if verbose:
        print 'Root CA is missing in chain'
    return False
    
if __name__ == "__main__":

    import optparse
    import os.path
    import sys

    usage= "usage: %prog [options] cert_file \n\nDo %prog -h for more help."
    
    parser = optparse.OptionParser(usage=usage, version ="%prog " + __version__)
    parser.add_option("-v", "--verbose", action = 'store_true', default= False,
                    help = "Enhance verbosity.")

    (options, args) = parser.parse_args()
    
    if not args:
        parser.error("incorrect number of arguments")

    filename = args[0] 

    if not os.path.isfile(filename):
        print "Error: '%s' is not a file or does not exist." % filename
        sys.exit(1)

    cert_list = certs_from_file(filename)
   
    ret =  verify_chain(cert_list, options.verbose)

    if ret == True:
        print 'OK: found valid and complete chain'
        sys.exit(0)
    else:
        print 'Error: incomplete or wrong chain'
        sys.exit(0)
