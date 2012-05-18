"""
myproxy library. Partially based  on m2crypto testing and demo code.
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



__author__ = "Placi Flury grid@switch.ch"
__date__ = "03.06.2011"
__version__ = "0.2.0"

import os, os.path, time, random, calendar
from hashlib import sha1
from M2Crypto import SSL, RSA, X509, EVP, BIO, ASN1, util
from M2Crypto import version as m2_version
from distutils import version

DEBUG = False

class MyProxyError(Exception):
    """ 
    Exception raised for MyProxy errors.
    Attributes:
        expression -- input expression in which error occurred
        message -- explanation of error 
    """
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        Exception.__init__(self)

    def __str__(self):
        return self.message

class MyProxyInputError(MyProxyError):
    """ Raised for wrong input parameters (types, values etc.)"""
    pass

class MyProxySSLError(MyProxyError):
    """ Raised for SSL errors, 
        e.g. context, connection, permission errors.
    """
    pass

class CredentialError(Exception):
    """ 
    Exception raised for Credential errors.
    Attributes:
        expression -- input expression in which error occurred
        message -- explanation of error 
    """
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        Exception.__init__(self)

    def __str__(self):
        return self.message
    
class UserCredentialError(CredentialError):
    """ Raised for errors with user credentials. """
    pass


class Credential(object):
    """ Handles key and certificate as M2Proxy RSA and X509 objects. """

    def __init__(self, keyfile=None, certfile=None, passphrase=None):
        """
        keyfile -- file where key is stored.  Must be PEM encoded.
        certfile -- file where certificate is stored. Must be PEM encoded. 
        passphrase -- of keyfile. If not passed an interactive prompt will be used.

        Notice, if only one of the key/cert file is defined, assumption is that 
        both are store in same file. 

        Raises: CrendentialError -- if any error occurs

        XXX: TODO: support DER format as well
        """
        self._key = None
        self._cert = None
        self._cert_chain = list() # certficate chain, excluding cert

        if keyfile or certfile:
            if not certfile:
                certfile = keyfile
            if not keyfile:
                keyfile = certfile

            self.read(keyfile, certfile, passphrase)
    
    def passwd_callback(self, v):
        return util.passphrase_callback(v, prompt1="Enter Credential passphrase", prompt2=None)


    def read(self, keyfile, certfile, passphrase=None):
        """ Reads key and cert, from files

            keyfile -- file where key is stored.  Must be PEM encoded.
            certfile -- file where certificate is stored. Must be PEM encoded. 
        
            Raises: CrendentialError -- if files can't be read, or keyfile not owned
                                    by running process
        """
        if keyfile:
            st = os.stat(keyfile)
            dir(st)
            user_id = os.geteuid()
            if st.st_uid != user_id:
                raise CredentialError("Keyfile error", 
                    "Keyfile '%s' not owned by user runnig process ('%d')" % \
                    (keyfile, user_id))
            try:
                key_bio = BIO.File(open(keyfile,'r'))
                if not passphrase:
                    self._key = RSA.load_key_bio(key_bio, self.passwd_callback)
                else:
                    self._key = RSA.load_key_bio(key_bio, 
                        lambda *args, **kw: passphrase)
                key_bio.close()
                
                cert_bio = BIO.File(open(certfile,'r'))
                self._cert = X509.load_cert_bio(cert_bio)
                while True:
                    crt = X509.load_cert_bio(cert_bio)
                    if  crt.verify() == 0: # XXX look for a more elegant way
                        break
                    self._cert_chain.append(crt)
                cert_bio.close()
            except Exception, err:
                raise CredentialError("Failed read", err.__str__())
            
        
    def get_cert(self):
        """ 
        Returns a X509 instance 
        """ 
        return self._cert

    def get_key(self):
        """
        Returns a RSA instance
        """
        return self._key

    def get_cert_chain(self):
        """
        Returns a the certificate chain. Is a list of X509 instances.
        May be empty if chain couldn't be populated.
        """
        return self._cert_chain

    def set_key(self, key):
        """
        key -- a RSA key instance
        """
        self._key = key

    def set_cert(self, cert):
        """
        cert -- a X509 cert instance
        """
        self._cert = cert

    def set_cert_chain(self, cert_chain):
        """
        cert_chain -- a list of X509 cert instances 
                which must issueing instances of the cert.
    
        raise CredentialError -- if chain does not match certificate, or is incomplete
        """
        self._cert_chain = cert_chain
        if not self.check_cert_chain():
            raise CredentialError("Cert Chain",
                "Certificate chain is either incomplete or wrong")
            
   
    def check_cert_chain(self):
        """ returns -- True if chain is complete
                        False for any other case 
        """ 
        if self._cert.check_ca() == 1:
            return True

        s_crt = self._cert
        for c in self._cert_chain:
            if s_crt.get_issuer().as_hash() != c.get_subject().as_hash():
                return False
            if c.check_ca() == 1:
                return True
            s_crt = c 
       
        return False


class ProxyCredential(Credential):
    """ Used to deal with proxy credentials. """
    
    def store_proxy(self, proxyfile):
        """
        Stores credential in proxyfile.
        """
        px = open(proxyfile, "w")
        bio = BIO.File(px)
        bio.write(self._cert.as_pem())
        self._key.save_key_bio(bio, cipher=None)
        for crt in self._cert_chain:
            bio.write(crt.as_pem())
        bio.close()
        os.chmod(proxyfile, 0600)

class UserCredential(Credential):
        
    """ Stores key and certificate as M2Proxy RSA and X509 objects. """

    def __init__(self, keyfile=None, certfile=None, passphrase=None):
        """
        keyfile -- file where key is stored.  Must be PEM encoded.
                [ default $HOME/.globus/userkey.pem]
        certfile -- file where certificate is stored. Must be PEM encoded. 
                [ default $HOME/.gobus/usercert.pem]

        Raises: UserCredentialError -- if keyfile, certfile could not be found 
                CredentialEror -- if files could not be read (and other errors)
        """
       
        if not certfile:
            certfile = os.path.join(os.getenv('HOME'), '.globus','usercert.pem')

        if not keyfile:
            keyfile = os.path.join(os.getenv('HOME'), '.globus','userkey.pem')

        if not os.path.exists(certfile):
            raise UserCredentialError("Certfile missing", 
                "Certificate file '%s' does not exist." % certfile)

        if not os.path.exists(keyfile):
            raise UserCredentialError("Keyfile missing", 
                "Keyfile '%s' does not exist." % keyfile)

        Credential.__init__(self, keyfile, certfile, passphrase)

    
            


class MyProxy(object):
    """ 
    This class provides an API for communicating with MyProxy servers. 
    It provides main functions for get, put and destroy
    credentials on MyProxy server. It also provides functions for getting 
    credential information and changing passwords. 
    (not yet fully implemented).
    """

    DEFAULT_PORT = 7512
    DEFAULT_LIFETIME = 43200    # [sec]

    # MyProxy server command 'codes'
    GET_PROXY = 0
    PUT_PROXY = 1
    INFO_PROXY = 2              # XXX not implemented
    DESTROY_PROXY = 3           # XXX not implemented
    CHANGE_PASSWORD = 4         # XXX not implemented
    
    # Constants    
    RESPONSE_OK = 0
    MIN_PASSWORD_LENGTH = 6 
    PROTOCOL_VERSION = 'MYPROXYv2'
    SSL_PROTOCOL = 'sslv3'
    CA_PATH = '/etc/grid-security/certificates'
    CMD_STR = """VERSION=%s\nCOMMAND=%d\nUSERNAME=%s\nPASSPHRASE=%s\nLIFETIME=%d\0"""
    ASN1_START = '\x30\x82'     # start token of serialized MyPorxy responses
    EXPIRATION_THRESH = 300     # Minimal remaining time a certificate needs to be valid 
                                # for being uploaded to MyProxy

    # http://dev.globus.org/wiki/Security/ProxyCertTypes  -> FOR OIDs
    KEY_USAGE_VALUE = "critical,digitalSignature, keyEncipherment"
    PX_CERTINFO_OID = 'OID:1.3.6.1.5.5.7.1.14'  
    PX_CERTINFO = 'proxyCertInfo'
    PCI_NORMAL_POLICY = "critical, language: 1.3.6.1.5.5.7.21.1"
    PCI_LIMITED_POLICY = "critical, language: 1.3.6.1.4.1.3536.1.1.1.9" 
    

    VALID_PX_TYPES = ['old','rfc']    # valid proxy types, which are:
                                                        # old - legacy globus proxy
                                                        # rfc - RFC3820 compliant proxy

    VALID_PX_POLICIES = ['normal', 'limited'] # valid proxy policies

    def __init__(self, host=None, port=7512, px_type = 'rfc', bits = 1024, px_policy='normal'):
        """
            Keyword arguments:
            host -- MyProxy server hostname  (default None, -> must be set later)
            port -- MyProxy server port  (default 7512)
            px_type -- Proxy type (limited, old, rfc), default = rfc
            bits -- key size of generated proxy

            raised -- MyProxyInputError if px_type is not supported or is invalid.

        """
        self._host = host
        self._port = port
        self._context = SSL.Context(MyProxy.SSL_PROTOCOL)
        self._px_validity_time = 7 * 86400  # validity of uploaded proxy (default 7 days)
        self._bits = bits
        if px_type not in MyProxy.VALID_PX_TYPES:
            raise MyProxyInputError('Invalid px_type', 
            "The specified px_type '%s' is not supported." % px_type ) 
        self._px_type = px_type
        
        if px_policy not in MyProxy.VALID_PX_POLICIES:
            raise MyProxyInputError('Invalid px_policy', 
            "The specified px_policy '%s' is not supported." % px_policy ) 
        self._px_policy = px_policy
 

    def _generate_signing_request(self, messageDigest = "sha1"):
        """
            Generates a certificate request, (re-) sets the proxykey variable
            Returns: key and csr (X509.Request)
        """
        csr = X509.Request()
        key = RSA.gen_key(self.get_key_size(), 65537)
            
        pkey = EVP.PKey()
        pkey.assign_rsa(key, capture=0)
        csr.set_pubkey(pkey)
        csr.sign(pkey, messageDigest)
            
        return key, csr


    def _check_server_status(self, connection):
        """
        Checks whether MyProxy server is fine with our previous query  
        (taken mostly verbatim from Tom Uram's MyProxyLogon code)

        connection -- connection 'object'
        raises -- MyProxyException for any negative response from server.
                Notice, this will close connection
        """
        msg  = connection.recv(8192)
        lines = msg.split('\n')
        # get response value
        responselines = filter(lambda x: x.startswith('RESPONSE'), lines)
        responseline = responselines[0]
        response = int(responseline.split('=')[1])
        # get error text
        errortext = ""
        errorlines = filter(lambda x: x.startswith('ERROR'), lines)
        for e in errorlines:
            etext = e.split('=')[1]
            errortext += etext
        
        if response != MyProxy.RESPONSE_OK:
            connection.close()
            raise MyProxyError("MyProxy Server Error", '%r' % errortext)


    def _generate_serial(self, pub_key):
        """
        Proxy Issuer MAY use a SHA-1 hash of the PC public key to assign a
        serial number with a high probability of uniqueness. (RFC 3820)

        return serial number (int)
        """
        h = sha1() # from hashlib
        h.update(pub_key.as_der())
        serial_hex = h.hexdigest()
        serial_int = int(serial_hex[:6], 16)  

        return serial_int


    def _get_secs2expiration(self, cert):
        """ returns seconds to expiration of 
            this certificate. (minus values 
            if it expired already)
        """
        enddate = cert.get_not_after().__str__()
        enddate_tuple = time.strptime(enddate, '%b %d %H:%M:%S %Y GMT')
        enddate_epoch = calendar.timegm(enddate_tuple)
        secs2exp = enddate_epoch - time.mktime(time.localtime())
        return int(secs2exp)


    def _create_proxy(self, credential):
        """ 
        Creates a proxy. Different flavors can be specified 
        by the 'px_type' variable

        credential -  Credential type object

        returns EVP proxykey, proxycert 
        raises: MyProxyInputError upon invalid input
                MyProxyError 
        """
        secs2exp = self._get_secs2expiration(credential.get_cert())
        if secs2exp < MyProxy.EXPIRATION_THRESH: 
            raise MyProxyError("Cert Validity Time", 
                "Certificate expires in '%d' seconds. Below threshold." % secs2exp)

        random.seed()
        proxycert = X509.X509()

        pk2 = EVP.PKey()
        proxykey =  RSA.gen_key(self.get_key_size(), 65537)
        pk2.assign_rsa(proxykey)
        proxycert.set_pubkey(pk2)
        proxycert.set_version(2)
        not_before = ASN1.ASN1_UTCTIME()
        not_after = ASN1.ASN1_UTCTIME()
        not_before.set_time(int(time.time()))
        offset = self._px_validity_time
        if offset > secs2exp:
            offset = secs2exp
        not_after.set_time(int(time.time()) + offset )
        proxycert.set_not_before(not_before)
        proxycert.set_not_after(not_after)
        proxycert.set_issuer_name(credential.get_cert().get_subject())
        serial = self._generate_serial(proxycert.get_pubkey())
        proxycert.set_serial_number(serial)
        issuer_name_string = credential.get_cert().get_subject().as_text()
        seq = issuer_name_string.split(",")

        px_type = self.get_proxy_type()
        px_policy = self.get_proxy_policy()

        pci_ext = X509.new_extension("keyUsage", MyProxy.KEY_USAGE_VALUE, 1)
        proxycert.add_ext(pci_ext)

        # legacy proxys have no extensions
        if px_type == 'old':
            if px_policy == 'limited':
                proxy_subject = 'limited proxy'
            else: 
                proxy_subject = 'proxy'

        elif px_type == 'rfc':
            proxy_subject = str(random.randint(10000000, 99999999))
            if px_policy == 'limited':
                pci_ext2 = X509.new_extension(MyProxy.PX_CERTINFO,
                     MyProxy.PCI_LIMITED_POLICY, 1)
            else:
                pci_ext2 = X509.new_extension(MyProxy.PX_CERTINFO, 
                    MyProxy.PCI_NORMAL_POLICY, 1)
            proxycert.add_ext(pci_ext2)
        else:
            # unknown px_type -> 
            raise MyProxyInputError('Invalid Proxy Type', \
                    "Type '%s' for proxy is invalid" % px_type)
            
        subject_name = X509.X509_Name()

        for entry in seq:
            l = entry.split("=")
            subject_name.add_entry_by_txt(field=l[0].strip(),
                                          type=ASN1.MBSTRING_ASC,
                                          entry=l[1], len=-1, loc=-1, set=0)

        subject_name.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                                      entry=proxy_subject, len=-1, loc=-1, set=0)

        proxycert.set_subject_name(subject_name)

        pk = EVP.PKey()
        pk.assign_rsa(credential.get_key(), capture=0)
        proxycert.sign(pk, 'sha1')

        return pk2, proxycert
 
    
    def _get_signing_request(self, der_blob):
        """ Extracts signing request from 
            MyProxy response. 
            
            der_blob --  sequence with PKCS10 encoded CSR string

            raise --  MyProxyError if no CSR could be extracted
        """
        ind = der_blob.find(MyProxy.ASN1_START)
        if ind < 0:
            raise MyProxyError("CSR missing", 
                "Could not extract any CSR from ASN1 sequence")
        _len = 256*ord(der_blob[ind+2]) + ord(der_blob[ind+3])

        c = der_blob[ind:ind+_len+4] # get CSR 
        
        if version.LooseVersion(m2_version) < '0.20': 
            # little hack to overcome missing method in versions < 0.20
            import tempfile
            tmp_fd, tmp_name = tempfile.mkstemp(suffix='.csr')
            f = os.fdopen(tmp_fd,'wb')
            f.write(c)
            f.close()
            req = X509.load_request(tmp_name, X509.FORMAT_DER)
            os.remove(tmp_name)
        else: 
            req = X509.load_request_der_string(c)
        return req

               
    def _get_certs(self, der_blob):
        """ 
            Extracts the  DER encoded certficates we 
            as received from the MyProxy server.

            taken from Tom Uram's MyProxyLogon code
            replaced crypto module dependencies

            der_blob -- DER encoded string with certificates

            returns: list of X509 objects, 
        """
        x509_list = []
        dat = der_blob
        
        while dat:
            ind = dat.find(MyProxy.ASN1_START)
            if ind < 0:
                break
            _len = 256*ord(dat[ind+2]) + ord(dat[ind+3])
            
            c = dat[ind:ind+_len+4] # get cert
            cert = X509.load_cert_string(c, X509.FORMAT_DER)
            x509_list.append(cert)
            dat = dat[ind + _len + 4:] 

        return x509_list
    
    def _check_fix_chain(self, credential):
        """ checks the certificate chain of given credential object. 
            If chain isn't complete it tries to fix it.

            credential -- credential object
        """

        crt = credential.get_cert()

        if credential.check_cert_chain():
            return
        chain = list() 
        while True:
            issuer = crt.get_issuer()
            # let's try to find issuer CA in MyProxy.CA_PATH
            # in Grids (EuGridPMA, the certificate files are the
            # cert hash valued + '.0' AFFIX
            _hash  = hex(issuer.as_hash())[2:].strip('L')  
            while len(_hash) < 8:  # padding
                _hash = '0' + _hash
            issuer_file = os.path.join(MyProxy.CA_PATH, (_hash +'.0'))
            if not os.path.exists(issuer_file): # XXX throw error..
                break 
            crt = X509.load_cert(issuer_file, X509.FORMAT_PEM)
            chain.append(crt)
            if crt.check_ca() != 0 and \
                (crt.get_subject().as_text() == crt.get_issuer().as_text()):
                break

        credential.set_cert_chain(chain) 
 
    def _px_sign_request(self, csr, credential):
        """ signing csr request with given credential.
            Notice, we create a proxy certificate, which
            is used to sign the csr

            returns proxy, signed certificate 
        """
        px_key, px = self._create_proxy(credential)
        pkey = csr.get_pubkey()
        
        ppx = X509.X509()
        ppx.set_version(2)
        ppx.set_pubkey(pkey) 
        ppx.set_serial_number(self._generate_serial(pkey))

        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(int(time.time()))
        ppx.set_not_before(not_before)
        ppx.set_not_after(px.get_not_after()) 
        ppx.set_issuer_name(px.get_subject())
        issuer_name_string = px.get_subject().as_text()
        seq = issuer_name_string.split(",")
        
        px_type = self.get_proxy_type()
        px_policy = self.get_proxy_policy()

        pci_ext = X509.new_extension("keyUsage", MyProxy.KEY_USAGE_VALUE, 1)
        ppx.add_ext(pci_ext)

        # legacy proxys have no extensions
        if px_type == 'old':
            if px_policy == 'limited':
                proxy_subject = 'limited proxy'
            else: 
                proxy_subject = 'proxy'

        elif px_type == 'rfc':
            proxy_subject = str(random.randint(10000000, 99999999))
            if px_policy == 'limited':
                pci_ext2 = X509.new_extension(MyProxy.PX_CERTINFO, 
                    MyProxy.PCI_LIMITED_POLICY, 1)
            else:
                pci_ext2 = X509.new_extension(MyProxy.PX_CERTINFO, 
                    MyProxy.PCI_NORMAL_POLICY, 1)
            ppx.add_ext(pci_ext2)
            
        else:
            # unknown px_type -> 
            raise MyProxyInputError('Invalid Proxy Type', \
                    "Type '%s' for proxy is invalid" % px_type)


        subject_name = X509.X509_Name()
        for entry in seq:
            l = entry.split("=")
            subject_name.add_entry_by_txt(field=l[0].strip(),
                                          type=ASN1.MBSTRING_ASC,
                                          entry=l[1], len=-1, loc=-1, set=0)

        subject_name.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                                      entry=proxy_subject, len=-1, loc=-1, set=0)
        ppx.set_subject(subject_name)
        ppx.sign(px_key,'sha1')
        return px, ppx

    def set_host(self, host):
        """ host -- MyProxy server hostname """
        self._host = host.strip()

    def get_host(self):
        """ Returns hostname of MyProxy server """
        return self._host 

    def set_port(self, port):
        """ port -- MyProxy server port 
            raises MyProxyInputError if port isn't an integer.
        """
        if type(port) != int:
            raise MyProxyInputError("Input Type", 
                "Port  must be an integer")
        self._port = port
 
    def get_port (self):
        """ Returns MyProxy sever port """
        return self._port

    def set_proxy_validity_time(self, validity_time):
        """ Sets validity time of the uploaded  myproxy 
            certificate. 
            validity_time -- value in seconds
        """
        self._px_validity_time = validity_time

    def get_proxy_validity_time(self):
        """ Returns the validity time, which is 
            used for uploading myproxy certificates.
        """
        return self._px_validity_time

    def set_key_size(self, bits):
        """ Sets siz of key in bits."""
        self._bits = bits

    def get_key_size(self):
        """ Returns key size in bits. """
        return self._bits

    def set_proxy_type(self, px_type):
        """ Sets type of proxy to generate. 
            valid values are:
                old - legacy globus proxy
                rfc - RFC3820 compliant proxy
 
            raises MyProxyInputError if specified type
            is not supported/valid.
        """
        if px_type not in MyProxy.VALID_PX_TYPES:
            raise MyProxyInputError('Invalid px_type', 
            "The specified px_type '%s' is not supported." % px_type ) 
        self._px_type = px_type

    def get_proxy_type(self):
        """ returns the type of the proxy 
            generated for uploading.
        """
        return self._px_type
    
    def set_proxy_policy(self, px_policy):
        """ Sets policy of proxy to generate. 
            valid values are:
                limited -- limited proxy
                normal  -- old style normal proxy
 
            raises MyProxyInputError if specified type
            is not supported/valid.
        """
        if px_policy not in MyProxy.VALID_PX_POLICIES:
            raise MyProxyInputError('Invalid policy_type', 
            "The specified px_policy '%s' is not supported." % px_policy ) 
        self._px_policy = px_policy

    def get_proxy_policy(self):
        """ returns the policy of the proxy 
            generated for uploading.
        """
        return self._px_policy

    def init_context(self, certfile=None, keyfile=None, passphrase=None):
        """ Initializes SSL Context for communication with MyProxy server.
            
            certfile - file (path)  of user/host certificate (default None)
            keyfile - file (path) of user/host key (default None)
            passphrase -- keyfile passphrase 
            
            raises: MyProxySSLError - for any context error
        
            Notice, if the certfile/keyfile are not found, we're setting up
            a context without client cert/key.
        """ 
        if keyfile: # owned by process check
            st = os.stat(keyfile)
            if st.st_uid != os.geteuid():
                raise MyProxySSLError("Keyfile owner", 
                    "Keyfile '%s' not owned by calling process." % keyfile)

        if  certfile and os.path.exists(certfile) and os.path.exists(keyfile):
            if passphrase:
                self._context.load_cert(certfile, keyfile,
                        lambda *args, **kw: passphrase)
            else:
                self._context.load_cert(certfile, keyfile)

        self._context.load_verify_locations(capath = MyProxy.CA_PATH)
        self._context.set_verify(SSL.verify_peer, 10) 
        #self._context.set_info_callback()   
        self._context.set_options(0x00000800L) # taken from Tom Uram
        

    def get(self, username, passphrase, lifetime=None):
        """ Retrieves delegated credentials from MyProxy server Anonymously 
            (without local credentials) 
            Notes: Performs simple verification of private/public keys of the 
            delegated credential.
            
            username -- the username of the credentials to retrieve
            passphrase -- the passphrase of the credentials to retrieve
            lifetime -- the requested lifetime of the retrieved credential, if not set
                        the default will be taken.
            
            Returns: ProxyCredential object

            Raises: MyProxyException - if any error occured during the operation
                    MyProxyInputError - for invalid input
        """
        if not lifetime:
            lifetime = MyProxy.DEFAULT_LIFETIME

        if type(lifetime) != int:
            raise MyProxyInputError("Input Type", 
                "Lifetime must be given in seconds (int)")

        cmd_get = MyProxy.CMD_STR % (MyProxy.PROTOCOL_VERSION, 
                MyProxy.GET_PROXY, username, passphrase, lifetime)

        conn = SSL.Connection(self._context)
        try:
            conn.connect((self._host, self._port))
            conn.write('0') # sending globus compat byte
            conn.write(cmd_get)
        except Exception, e:
            conn.close()
            raise MyProxyError("Connection Error", '%r' % e)
        
        self._check_server_status(conn)
       
        key, csr = self._generate_signing_request()
        try:
            conn.send(csr.as_der())
            _byte1 = conn.recv(1) # first byte holds numbers of certs
            numcerts = ord(_byte1[0])
            certs_blob = conn.recv(8192)
        except Exception, e:
            conn.close()
            raise MyProxyError("Connection Error", '%r' % e)
        
        self._check_server_status(conn)
       
        certs = self._get_certs(certs_blob)
        if len(certs) != numcerts:
            conn.close()
            raise MyProxyError("MyProxy Certificates Error", 
                " %d certs expected, %d received" % (numcerts, len(certs)))

        conn.close()

        px = ProxyCredential()
        px.set_key(key)
        px.set_cert(certs[0])
        px.set_cert_chain(certs[1:])

        return px

    def put(self, credential, username, passphrase, lifetime=None):
        """
            Delegates credential to the MyProxy server.
            
            Parameters:
            credential -- Credential Object 
            username -- identifies the account in which to store the credential
            passphrase -- passphrase for protecting the proxy credential
            lifetime -- sets max lifetime allowed for retrieved proxy credentials (in secs).
                        If lifetime not set, we'll set it to a libraries default value.

            Raises: MyProxyException - if any error occured during the operation
                    MyProxyInputError - for invalid input

        """
        if not lifetime:
            lifetime = MyProxy.DEFAULT_LIFETIME

        if type(lifetime) != int:
            raise MyProxyInputError("Input Type",
                "Lifetime must be given in seconds (int)")

        self._check_fix_chain(credential)

        cmd_put = MyProxy.CMD_STR % (MyProxy.PROTOCOL_VERSION, 
                    MyProxy.PUT_PROXY,
                    username, passphrase, lifetime)
          
        conn = SSL.Connection(self._context)
        
        try:
            conn.connect((self._host, self._port))
            conn.write('0') # sending globus compat byte
            conn.write(cmd_put)
        except Exception, e:
            conn.close()
            raise MyProxyError("Connection Error", '%r' % e)

        self._check_server_status(conn)

        try:
            csr = self._get_signing_request(conn.recv(8192))
        except Exception, e:
            conn.close()
            raise e
        px, crt = self._px_sign_request(csr, credential) 
        chain = credential.get_cert_chain()
        n_certs = '%c' % (len(chain) + 3) # 'convert to 1 byte unsigned
        crt_str = n_certs + crt.as_der() + px.as_der() \
                 + credential.get_cert().as_der()
       
 
        for c in chain:
            crt_str += c.as_der()
        
        if DEBUG:
            _proxyfile = 'upload_px_%s_%s.pem' % \
                 (self.get_proxy_type(), self.get_proxy_policy())
            _pxf = open(_proxyfile, "w")
            bio = BIO.File(_pxf)
            bio.write(crt.as_pem())
            bio.write(px.as_pem())
            bio.write(credential.get_cert().as_pem())
            for c in chain:
                bio.write(c.as_pem())
            bio.close()
            os.chmod(_proxyfile, 0600)

        try:
            conn.send(crt_str)
        except Exception, e:
            conn.close()
            raise MyProxyError("Connection Error", '%r' % e)

        self._check_server_status(conn)
        conn.close()
