from copy import copy

class DStruct(object):
    """
    Simple dynamic structure, like :const:`collections.namedtuple` but more flexible
    (and less memory-efficient)
    """
    # Default arguments. Defaults are *shallow copied*, to allow defaults such as [].
    _fields = []
    _defaults = {}

    def __init__(self, *args_t, **args_d):
        # order
        if len(args_t) > len(self._fields):
            raise TypeError("Number of arguments is larger than of predefined fields")
        # Copy default values
        for (k, v) in self._defaults.items():
            self.__dict__[k] = copy(v)
        # Set pass by value arguments
        self.__dict__.update(zip(self._fields, args_t))
        # dict
        self.__dict__.update(args_d)

    def __repr__(self):
        return '{module}.{classname}({slots})'.format(
            module=self.__class__.__module__, classname=self.__class__.__name__,
            slots=", ".join('{k}={v!r}'.format(k=k, v=v) for k, v in
                            self.__dict__.items()))

# ********************************************************
# ********************************************************
# ********************************************************

class BitcoinException(Exception):
    """
    Base class for exceptions received from Bitcoin server.
    - *code* -- Error code from ``bitcoind``.
    """
    # Standard JSON-RPC 2.0 errors
    INVALID_REQUEST  = -32600,
    METHOD_NOT_FOUND = -32601,
    INVALID_PARAMS   = -32602,
    INTERNAL_ERROR   = -32603,
    PARSE_ERROR      = -32700,

    # General application defined errors
    MISC_ERROR                  = -1  # std::exception thrown in command handling
    FORBIDDEN_BY_SAFE_MODE      = -2  # Server is in safe mode, and command is not allowed in safe mode
    TYPE_ERROR                  = -3  # Unexpected type was passed as parameter
    INVALID_ADDRESS_OR_KEY      = -5  # Invalid address or key
    OUT_OF_MEMORY               = -7  # Ran out of memory during operation
    INVALID_PARAMETER           = -8  # Invalid, missing or duplicate parameter
    DATABASE_ERROR              = -20 # Database error
    DESERIALIZATION_ERROR       = -22 # Error parsing or validating structure in raw format

    # P2P client errors
    CLIENT_NOT_CONNECTED        = -9  # Bitcoin is not connected
    CLIENT_IN_INITIAL_DOWNLOAD  = -10 # Still downloading initial blocks

    # Wallet errors
    WALLET_ERROR                = -4  # Unspecified problem with wallet (key not found etc.)
    WALLET_INSUFFICIENT_FUNDS   = -6  # Not enough funds in wallet or account
    WALLET_INVALID_ACCOUNT_NAME = -11 # Invalid account name
    WALLET_KEYPOOL_RAN_OUT      = -12 # Keypool ran out, call keypoolrefill first
    WALLET_UNLOCK_NEEDED        = -13 # Enter the wallet passphrase with walletpassphrase first
    WALLET_PASSPHRASE_INCORRECT = -14 # The wallet passphrase entered was incorrect
    WALLET_WRONG_ENC_STATE      = -15 # Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    WALLET_ENCRYPTION_FAILED    = -16 # Failed to encrypt the wallet
    WALLET_ALREADY_UNLOCKED     = -17 # Wallet is already unlocked

    def __init__(self, error):
        Exception.__init__(self, error['message'])
        self.code = error['code']


class TransportException(Exception):
    """
    Class to define transport-level failures.
    """
    def __init__(self, msg, code=None, protocol=None, raw_detail=None):
        self.msg = msg
        self.code = code
        self.protocol = protocol
        self.raw_detail = raw_detail
        self.s = """
        Transport-level failure: {msg}
        Code: {code}
        Protocol: {protocol}
        """.format(msg=msg, code=code, protocol=protocol)

    def __str__(self):
        return self.s


##### General application defined errors
class SafeMode(BitcoinException):
    """
    Operation denied in safe mode (run ``bitcoind`` with ``-disablesafemode``).
    """


class JSONTypeError(BitcoinException):
    """
    Unexpected type was passed as parameter
    """
InvalidAmount = JSONTypeError  # Backwards compatibility


class InvalidAddressOrKey(BitcoinException):
    """
    Invalid address or key.
    """
InvalidTransactionID = InvalidAddressOrKey  # Backwards compatibility


class OutOfMemory(BitcoinException):
    """
    Out of memory during operation.
    """


class InvalidParameter(BitcoinException):
    """
    Invalid parameter provided to RPC call.
    """


##### Client errors
class ClientException(BitcoinException):
    """
    P2P network error.
    This exception is never raised but functions as a superclass
    for other P2P client exceptions.
    """


class NotConnected(ClientException):
    """
    Not connected to any peers.
    """


class DownloadingBlocks(ClientException):
    """
    Client is still downloading blocks.
    """


##### Wallet errors
class WalletError(BitcoinException):
    """
    Unspecified problem with wallet (key not found etc.)
    """
SendError = WalletError  # Backwards compatibility


class InsufficientFunds(WalletError):
    """
    Insufficient funds to complete transaction in wallet or account
    """


class InvalidAccountName(WalletError):
    """
    Invalid account name
    """


class KeypoolRanOut(WalletError):
    """
    Keypool ran out, call keypoolrefill first
    """


class WalletUnlockNeeded(WalletError):
    """
    Enter the wallet passphrase with walletpassphrase first
    """


class WalletPassphraseIncorrect(WalletError):
    """
    The wallet passphrase entered was incorrect
    """


class WalletWrongEncState(WalletError):
    """
    Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    """


class WalletEncryptionFailed(WalletError):
    """
    Failed to encrypt the wallet
    """


class WalletAlreadyUnlocked(WalletError):
    """
    Wallet is already unlocked
    """


# For convenience, we define more specific exception classes
# for the more common errors.
_exception_map = {
    BitcoinException.FORBIDDEN_BY_SAFE_MODE: SafeMode,
    BitcoinException.TYPE_ERROR: JSONTypeError,
    BitcoinException.WALLET_ERROR: WalletError,
    BitcoinException.INVALID_ADDRESS_OR_KEY: InvalidAddressOrKey,
    BitcoinException.WALLET_INSUFFICIENT_FUNDS: InsufficientFunds,
    BitcoinException.OUT_OF_MEMORY: OutOfMemory,
    BitcoinException.INVALID_PARAMETER: InvalidParameter,
    BitcoinException.CLIENT_NOT_CONNECTED: NotConnected,
    BitcoinException.CLIENT_IN_INITIAL_DOWNLOAD: DownloadingBlocks,
    BitcoinException.WALLET_INSUFFICIENT_FUNDS: InsufficientFunds,
    BitcoinException.WALLET_INVALID_ACCOUNT_NAME: InvalidAccountName,
    BitcoinException.WALLET_KEYPOOL_RAN_OUT: KeypoolRanOut,
    BitcoinException.WALLET_UNLOCK_NEEDED: WalletUnlockNeeded,
    BitcoinException.WALLET_PASSPHRASE_INCORRECT: WalletPassphraseIncorrect,
    BitcoinException.WALLET_WRONG_ENC_STATE: WalletWrongEncState,
    BitcoinException.WALLET_ENCRYPTION_FAILED: WalletEncryptionFailed,
    BitcoinException.WALLET_ALREADY_UNLOCKED: WalletAlreadyUnlocked,
}


def wrap_exception(error):
    """
    Convert a JSON error object to a more specific Bitcoin exception.
    """
    # work around to temporarily fix https://github.com/bitcoin/bitcoin/issues/3007
    if error['code'] == BitcoinException.WALLET_ERROR and error['message'] == u'Insufficient funds':
        error['code'] = BitcoinException.WALLET_INSUFFICIENT_FUNDS
    return _exception_map.get(error['code'], BitcoinException)(error)


# ********************************************************
# ********************************************************
# ********************************************************

class ServerInfo(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.getinfo`.
    - *errors* -- Number of errors.
    - *blocks* -- Number of blocks.
    - *paytxfee* -- Amount of transaction fee to pay.
    - *keypoololdest* -- Oldest key in keypool.
    - *genproclimit* -- Processor limit for generation.
    - *connections* -- Number of connections to other clients.
    - *difficulty* -- Current generating difficulty.
    - *testnet* -- True if connected to testnet, False if on real network.
    - *version* -- Bitcoin client version.
    - *proxy* -- Proxy configured in client.
    - *hashespersec* -- Number of hashes per second (if generation enabled).
    - *balance* -- Total current server balance.
    - *generate* -- True if generation enabled, False if not.
    - *unlocked_until* -- Timestamp (seconds since epoch) after which the wallet
                          will be/was locked (if wallet encryption is enabled).
    """


class AccountInfo(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.listreceivedbyaccount`.
    - *account* -- The account of the receiving address.
    - *amount* -- Total amount received by the address.
    - *confirmations* -- Number of confirmations of the most recent transaction included.
    """


class AddressInfo(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.listreceivedbyaddress`.
    - *address* -- Receiving address.
    - *account* -- The account of the receiving address.
    - *amount* -- Total amount received by the address.
    - *confirmations* -- Number of confirmations of the most recent transaction included.
    """


class TransactionInfo(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.listtransactions`.
    - *account* -- account name.
    - *address* -- the address bitcoins were sent to, or received from.
    
    - *category* -- will be generate, send, receive, or move.
    - *amount* -- amount of transaction.
    - *fee* -- Fee (if any) paid (only for send transactions).
    - *confirmations* -- number of confirmations (only for generate/send/receive).
    - *txid* -- transaction ID (only for generate/send/receive).
    - *otheraccount* -- account funds were moved to or from (only for move).
    - *message* -- message associated with transaction (only for send).
    - *to* -- message-to associated with transaction (only for send).
    """


class AddressValidation(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.validateaddress`.
    - *isvalid* -- Validatity of address (:const:`True` or :const:`False`).
    - *ismine* -- :const:`True` if the address is in the server's wallet.
    - *address* -- Bitcoin address.
    """


class WorkItem(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.getwork`.
    - *midstate* -- Precomputed hash state after hashing the first half of the data.
    - *data* -- Block data.
    - *hash1* -- Formatted hash buffer for second hash.
    - *target* -- Little endian hash target.
    """


class MiningInfo(DStruct):
    """
    Information object returned by :func:`~bitcoinrpc.connection.BitcoinConnection.getmininginfo`.
    - *blocks* -- Number of blocks.
    - *currentblocksize* -- Size of current block.
    - *currentblocktx* -- Number of transactions in current block.
    - *difficulty* -- Current generating difficulty.
    - *errors* -- Number of errors.
    - *generate* -- True if generation enabled, False if not.
    - *genproclimit* -- Processor limit for generation.
    - *hashespersec* -- Number of hashes per second (if generation enabled).
    - *pooledtx* -- Number of pooled transactions.
    - *testnet* -- True if connected to testnet, False if on real network.
    """

# ********************************************************
# ********************************************************
# ********************************************************

try:
    import http.client as httplib
except ImportError:
    import httplib
import base64
import json
import decimal
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from collections import defaultdict, deque
###HONG### from bitcoinrpc.exceptions import TransportException

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 30


class JSONRPCException(Exception):
    def __init__(self, rpc_error):
        Exception.__init__(self)
        self.error = rpc_error


class HTTPTransport(object):
    def __init__(self, service_url):
        self.service_url = service_url
        self.parsed_url = urlparse.urlparse(service_url)
        if self.parsed_url.port is None:
            port = 80
        else:
            port = self.parsed_url.port
        authpair = "%s:%s" % (self.parsed_url.username,
                              self.parsed_url.password)
        authpair = authpair.encode('utf8')
        self.auth_header = "Basic ".encode('utf8') + base64.b64encode(authpair)
        if self.parsed_url.scheme == 'https':
            self.connection = httplib.HTTPSConnection(self.parsed_url.hostname,
                                                      port, None, None, False,
                                                      HTTP_TIMEOUT)
        else:
            self.connection = httplib.HTTPConnection(self.parsed_url.hostname,
                                                     port, False, HTTP_TIMEOUT)

    def request(self, serialized_data):
        if 0 :
            print("------------------------------------------")
            print("[RAW REQ]")
            print serialized_data
            print("------------------------------------------\n")
        self.connection.request('POST', self.parsed_url.path, serialized_data,
                                {'Host': self.parsed_url.hostname,
                                 'User-Agent': USER_AGENT,
                                 'Authorization': self.auth_header,
                                 'Content-type': 'application/json'})
        httpresp = self.connection.getresponse()
        if httpresp is None:
            self._raise_exception({
                'code': -342, 'message': 'missing HTTP response from server'})
        elif httpresp.status == httplib.FORBIDDEN:
            msg = "bitcoind returns 403 Forbidden. Is your IP allowed?"
            raise TransportException(msg, code=403,
                                     protocol=self.parsed_url.scheme,
                                     raw_detail=httpresp)
        
        resp = httpresp.read()
        if 0:
            print("------------------------------------------")
            print("[RAW RSP]")
            print resp
            print("------------------------------------------\n")
        #return resp.decode('utf8')
        objDecode = resp.decode('utf8')
        #json_obj = json.loads(resp)
        #print("zzz------------------------------------------\n")
        #print json_obj
        #print("zzz------------------------------------------\n")
        return objDecode


class FakeTransport(object):
    """A simple testing facility."""
    def __init__(self):
        self._data = defaultdict(deque)

    def load_serialized(self, method_name, fixture):
        self._data[method_name].append(fixture)

    def load_raw(self, method_name, fixture):
        self._data[method_name].append(json.dumps(fixture))

    def request(self, serialized_data):
        #data = json.loads(serialized_data, parse_int=decimal.Decimal, parse_float=decimal.Decimal)
        data = json.loads(serialized_data)
        method_name = data['method']
        return self._data[method_name].popleft()


class RPCMethod(object):
    def __init__(self, name, service_proxy):
        self._method_name = name
        self._service_proxy = service_proxy

    def __getattr__(self, name):
        new_name = '{}.{}'.format(self._method_name, name)
        return RPCMethod(new_name, self._service_proxy)

    def __call__(self, *args):
        self._service_proxy._id_counter += 1
        
        data = {'params': args,
                'method': self._method_name,
                'id': self._service_proxy._id_counter}
        """        
        data = {'version': '1.1',
                'method': self._method_name,
                'params': args,
                'id': self._service_proxy._id_counter}
        """        
        postdata = json.dumps(data)
        resp = self._service_proxy._transport.request(postdata)
        #resp = json.loads(resp, parse_float=decimal.Decimal)
        resp = json.loads(resp)

        if resp['error'] is not None:
            self._service_proxy._raise_exception(resp['error'])
        elif 'result' not in resp:
            self._service_proxy._raise_exception({
                'code': -343, 'message': 'missing JSON-RPC result'})
        else:
            return resp['result']

    def __repr__(self):
        return '<RPCMethod object "{name}">'.format(name=self._method_name)


class AuthServiceProxy(object):
    """
    You can use custom transport to test your app's behavior without calling
    the remote service.
    exception_wrapper is a callable accepting a dictionary containing error
    code and message and returning a suitable exception object.
    """
    def __init__(self, service_url, transport=None, exception_wrapper=None):
        self._service_url = service_url
        self._id_counter = 0
        self._transport = (HTTPTransport(service_url) if transport is None
                           else transport)
        self._exception_wrapper = exception_wrapper

    def __getattr__(self, name):
        return RPCMethod(name, self)

    def _get_method(self, name):
        """
        Get method instance when the name contains forbidden characters or
        already taken by internal attribute.
        """
        return RPCMethod(name, self)

    def _raise_exception(self, error):
        if self._exception_wrapper is None:
            raise JSONRPCException(error)
        else:
            raise self._exception_wrapper(error)



# ********************************************************
# ********************************************************
# ********************************************************


class BitcoinConnection(object):
    """
    A BitcoinConnection object defines a connection to a bitcoin server.
    It is a thin wrapper around a JSON-RPC API connection.
    Arguments to constructor:
    - *user* -- Authenticate as user.
    - *password* -- Authentication password.
    - *host* -- Bitcoin JSON-RPC host.
    - *port* -- Bitcoin JSON-RPC port.
    """
    def __init__(self, user, password, host='localhost', port=8332,
                 use_https=False):
        """
        Create a new bitcoin server connection.
        """
        url = 'http{s}://{user}:{password}@{host}:{port}/'.format(
            s='s' if use_https else '',
            user=user, password=password, host=host, port=port)
        self.url = url
        self.proxy = AuthServiceProxy(url, exception_wrapper=wrap_exception)

    def stop(self):
        """
        Stop bitcoin server.
        """
        self.proxy.stop()

    def getblock(self, hash):
        """
        Returns information about the given block hash.
        """
        return self.proxy.getblock(hash)

    def getblockwithlevel(self, hash, level):
        """
        Returns information about the given block hash.
        """
        return self.proxy.getblock(hash, level)

    def getblockcount(self):
        """
        Returns the number of blocks in the longest block chain.
        """
        return self.proxy.getblockcount()

    def getblockhash(self, index):
        """
        Returns hash of block in best-block-chain at index.
        :param index: index ob the block
        """
        return self.proxy.getblockhash(index)

    def getblocknumber(self):
        """
        Returns the block number of the latest block in the longest block chain.
        Deprecated. Use getblockcount instead.
        """
        return self.getblockcount()

    def getconnectioncount(self):
        """
        Returns the number of connections to other nodes.
        """
        return self.proxy.getconnectioncount()

    def getdifficulty(self):
        """
        Returns the proof-of-work difficulty as a multiple of the minimum difficulty.
        """
        return self.proxy.getdifficulty()

    def getgenerate(self):
        """
        Returns :const:`True` or :const:`False`, depending on whether generation is enabled.
        """
        return self.proxy.getgenerate()

    def setgenerate(self, generate, genproclimit=None):
        """
        Enable or disable generation (mining) of coins.
        Arguments:
        - *generate* -- is :const:`True` or :const:`False` to turn generation on or off.
        - *genproclimit* -- Number of processors that are used for generation, -1 is unlimited.
        """
        if genproclimit is None:
            return self.proxy.setgenerate(generate)
        else:
            return self.proxy.setgenerate(generate, genproclimit)

    def gethashespersec(self):
        """
        Returns a recent hashes per second performance measurement while generating.
        """
        return self.proxy.gethashespersec()

    def getinfo(self):
        """
        Returns an :class:`~bitcoinrpc.data.ServerInfo` object containing various state info.
        """
        #return ServerInfo(**self.proxy.getinfo())
        return self.proxy.getinfo()

    def getmininginfo(self):
        """
        Returns an :class:`~bitcoinrpc.data.MiningInfo` object containing various
        mining state info.
        """
        return MiningInfo(**self.proxy.getmininginfo())

    def getnewaddress(self, account=None):
        """
        Returns a new bitcoin address for receiving payments.
        Arguments:
        - *account* -- If account is specified (recommended), it is added to the address book
          so that payments received with the address will be credited to it.
        """
        if account is None:
            return self.proxy.getnewaddress()
        else:
            return self.proxy.getnewaddress(account)

    def getaccountaddress(self, account):
        """
        Returns the current bitcoin address for receiving payments to an account.
        Arguments:
        - *account* -- Account for which the address should be returned.
        """
        return self.proxy.getaccountaddress(account)

    def setaccount(self, bitcoinaddress, account):
        """
        Sets the account associated with the given address.
        Arguments:
        - *bitcoinaddress* -- Bitcoin address to associate.
        - *account* -- Account to associate the address to.
        """
        return self.proxy.setaccount(bitcoinaddress, account)

    def getaccount(self, bitcoinaddress):
        """
        Returns the account associated with the given address.
        Arguments:
        - *bitcoinaddress* -- Bitcoin address to get account for.
        """
        return self.proxy.getaccount(bitcoinaddress)

    def getaddressesbyaccount(self, account):
        """
        Returns the list of addresses for the given account.
        Arguments:
        - *account* -- Account to get list of addresses for.
        """
        return self.proxy.getaddressesbyaccount(account)

    def sendtoaddress(self, bitcoinaddress, amount, comment=None, comment_to=None):
        """
        Sends *amount* from the server's available balance to *bitcoinaddress*.
        Arguments:
        - *bitcoinaddress* -- Bitcoin address to send to.
        - *amount* -- Amount to send (float, rounded to the nearest 0.00000001).
        - *minconf* -- Minimum number of confirmations required for transferred balance.
        - *comment* -- Comment for transaction.
        - *comment_to* -- Comment for to-address.
        """
        if comment is None:
            return self.proxy.sendtoaddress(bitcoinaddress, amount)
        elif comment_to is None:
            return self.proxy.sendtoaddress(bitcoinaddress, amount, comment)
        else:
            return self.proxy.sendtoaddress(bitcoinaddress, amount, comment, comment_to)

    def getreceivedbyaddress(self, bitcoinaddress, minconf=1):
        """
        Returns the total amount received by a bitcoin address in transactions with at least a
        certain number of confirmations.
        Arguments:
        - *bitcoinaddress* -- Address to query for total amount.
        - *minconf* -- Number of confirmations to require, defaults to 1.
        """
        return self.proxy.getreceivedbyaddress(bitcoinaddress, minconf)

    def getreceivedbyaccount(self, account, minconf=1):
        """
        Returns the total amount received by addresses with an account in transactions with
        at least a certain number of confirmations.
        Arguments:
        - *account* -- Account to query for total amount.
        - *minconf* -- Number of confirmations to require, defaults to 1.
        """
        return self.proxy.getreceivedbyaccount(account, minconf)

    def gettransaction(self, txid):
        """
        Get detailed information about transaction
        Arguments:
        - *txid* -- Transactiond id for which the info should be returned
        """
        return TransactionInfo(**self.proxy.gettransaction(txid))

    def getrawtransaction(self, txid, verbose=True):
        """
        Get transaction raw info
        Arguments:
        - *txid* -- Transactiond id for which the info should be returned.
        - *verbose* -- If False, return only the "hex" of the transaction.
        """
        if verbose:
            return TransactionInfo(**self.proxy.getrawtransaction(txid, 1))
        return self.proxy.getrawtransaction(txid, 0)

    def gettxout(self, txid, index, mempool=True):
        """
        Returns details about an unspent transaction output (UTXO)
        Arguments:
        - *txid* -- Transactiond id for which the info should be returned.
        - *index* -- The output index.
        - *mempool* -- Add memory pool transactions.
        """
        tx = self.proxy.gettxout(txid, index, mempool)
        if tx != None:
            return TransactionInfo(**tx)
        else:
            return TransactionInfo()

    def createrawtransaction(self, inputs, outputs):
        """
        Creates a raw transaction spending given inputs
        (a list of dictionaries, each containing a transaction id and an output number),
        sending to given address(es).
        Returns hex-encoded raw transaction.
        Example usage:
        >>> conn.createrawtransaction(
                [{"txid": "a9d4599e15b53f3eb531608ddb31f48c695c3d0b3538a6bda871e8b34f2f430c",
                  "vout": 0}],
                {"mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT":50})
        Arguments:
        - *inputs* -- A list of {"txid": txid, "vout": n} dictionaries.
        - *outputs* -- A dictionary mapping (public) addresses to the amount
                       they are to be paid.
        """
        return self.proxy.createrawtransaction(inputs, outputs)

    def signrawtransaction(self, hexstring, previous_transactions=None, private_keys=None):
        """
        Sign inputs for raw transaction (serialized, hex-encoded).
        Returns a dictionary with the keys:
            "hex": raw transaction with signature(s) (hex-encoded string)
            "complete": 1 if transaction has a complete set of signature(s), 0 if not
        Arguments:
        - *hexstring* -- A hex string of the transaction to sign.
        - *previous_transactions* -- A (possibly empty) list of dictionaries of the form:
            {"txid": txid, "vout": n, "scriptPubKey": hex, "redeemScript": hex}, representing
            previous transaction outputs that this transaction depends on but may not yet be
            in the block chain.
        - *private_keys* -- A (possibly empty) list of base58-encoded private
            keys that, if given, will be the only keys used to sign the transaction.
        """
        return dict(self.proxy.signrawtransaction(hexstring, previous_transactions, private_keys))

    def decoderawtransaction(self, hexstring):
        """
        Produces a human-readable JSON object for a raw transaction.
        Arguments:
        - *hexstring* -- A hex string of the transaction to be decoded.
        """
        return dict(self.proxy.decoderawtransaction(hexstring))

    def listsinceblock(self, block_hash):
        res = self.proxy.listsinceblock(block_hash)
        res['transactions'] = [TransactionInfo(**x) for x in res['transactions']]
        return res

    def listreceivedbyaddress(self, minconf=1, includeempty=False):
        """
        Returns a list of addresses.
        Each address is represented with a :class:`~bitcoinrpc.data.AddressInfo` object.
        Arguments:
        - *minconf* -- Minimum number of confirmations before payments are included.
        - *includeempty* -- Whether to include addresses that haven't received any payments.
        """
        return [AddressInfo(**x) for x in
                self.proxy.listreceivedbyaddress(minconf, includeempty)]

    def listaccounts(self, minconf=1, as_dict=False):
        """
        Returns a list of account names.
        Arguments:
        - *minconf* -- Minimum number of confirmations before payments are included.
        - *as_dict* -- Returns a dictionary of account names, with their balance as values.
        """
        if as_dict:
            return dict(self.proxy.listaccounts(minconf))
        else:
            return self.proxy.listaccounts(minconf).keys()

    def listreceivedbyaccount(self, minconf=1, includeempty=False):
        """
        Returns a list of accounts.
        Each account is represented with a :class:`~bitcoinrpc.data.AccountInfo` object.
        Arguments:
        - *minconf* -- Minimum number of confirmations before payments are included.
        - *includeempty* -- Whether to include addresses that haven't received any payments.
        """
        return [AccountInfo(**x) for x in
                self.proxy.listreceivedbyaccount(minconf, includeempty)]

    def listtransactions(self, account=None, count=10, from_=0, address=None):
        """
        Returns a list of the last transactions for an account.
        Each transaction is represented with a :class:`~bitcoinrpc.data.TransactionInfo` object.
        Arguments:
        - *account* -- Account to list transactions from. Return transactions from
                       all accounts if None.
        - *count* -- Number of transactions to return.
        - *from_* -- Skip the first <from_> transactions.
        - *address* -- Receive address to consider
        """
        accounts = [account] if account is not None else self.listaccounts(as_dict=True).keys()
        return [TransactionInfo(**tx) for acc in accounts for
                tx in self.proxy.listtransactions(acc, count, from_) if
                address is None or tx["address"] == address]

    def backupwallet(self, destination):
        """
        Safely copies ``wallet.dat`` to *destination*, which can be a directory or a path
        with filename.
        Arguments:
        - *destination* -- directory or path with filename to backup wallet to.
        """
        return self.proxy.backupwallet(destination)

    def validateaddress(self, validateaddress):
        """
        Validate a bitcoin address and return information for it.
        The information is represented by a :class:`~bitcoinrpc.data.AddressValidation` object.
        Arguments: -- Address to validate.
        - *validateaddress*
        """
        return AddressValidation(**self.proxy.validateaddress(validateaddress))

    def getbalance(self, account=None, minconf=None):
        """
        Get the current balance, either for an account or the total server balance.
        Arguments:
        - *account* -- If this parameter is specified, returns the balance in the account.
        - *minconf* -- Minimum number of confirmations required for transferred balance.
        """
        args = []
        if account is not None:
            args.append(account)
            if minconf is not None:
                args.append(minconf)
        return self.proxy.getbalance(*args)

    def move(self, fromaccount, toaccount, amount, minconf=1, comment=None):
        """
        Move from one account in your wallet to another.
        Arguments:
        - *fromaccount* -- Source account name.
        - *toaccount* -- Destination account name.
        - *amount* -- Amount to transfer.
        - *minconf* -- Minimum number of confirmations required for transferred balance.
        - *comment* -- Comment to add to transaction log.
        """
        if comment is None:
            return self.proxy.move(fromaccount, toaccount, amount, minconf)
        else:
            return self.proxy.move(fromaccount, toaccount, amount, minconf, comment)

    def sendfrom(self, fromaccount, tobitcoinaddress, amount, minconf=1, comment=None,
                 comment_to=None):
        """
        Sends amount from account's balance to bitcoinaddress. This method will fail
        if there is less than amount bitcoins with minconf confirmations in the account's
        balance (unless account is the empty-string-named default account; it
        behaves like the sendtoaddress method). Returns transaction ID on success.
        Arguments:
        - *fromaccount* -- Account to send from.
        - *tobitcoinaddress* -- Bitcoin address to send to.
        - *amount* -- Amount to send (float, rounded to the nearest 0.01).
        - *minconf* -- Minimum number of confirmations required for transferred balance.
        - *comment* -- Comment for transaction.
        - *comment_to* -- Comment for to-address.
        """
        if comment is None:
            return self.proxy.sendfrom(fromaccount, tobitcoinaddress, amount, minconf)
        elif comment_to is None:
            return self.proxy.sendfrom(fromaccount, tobitcoinaddress, amount, minconf, comment)
        else:
            return self.proxy.sendfrom(fromaccount, tobitcoinaddress, amount, minconf,
                                       comment, comment_to)

    def sendmany(self, fromaccount, todict, minconf=1, comment=None):
        """
        Sends specified amounts from account's balance to bitcoinaddresses. This method will fail
        if there is less than total amount bitcoins with minconf confirmations in the account's
        balance (unless account is the empty-string-named default account; Returns transaction ID
        on success.
        Arguments:
        - *fromaccount* -- Account to send from.
        - *todict* -- Dictionary with Bitcoin addresses as keys and amounts as values.
        - *minconf* -- Minimum number of confirmations required for transferred balance.
        - *comment* -- Comment for transaction.
        """
        if comment is None:
            return self.proxy.sendmany(fromaccount, todict, minconf)
        else:
            return self.proxy.sendmany(fromaccount, todict, minconf, comment)

    def verifymessage(self, bitcoinaddress, signature, message):
        """
        Verifies a signature given the bitcoinaddress used to sign,
        the signature itself, and the message that was signed.
        Returns :const:`True` if the signature is valid, and :const:`False` if it is invalid.
        Arguments:
        - *bitcoinaddress* -- the bitcoinaddress used to sign the message
        - *signature* -- the signature to be verified
        - *message* -- the message that was originally signed
        """
        return self.proxy.verifymessage(bitcoinaddress, signature, message)

    def getwork(self, data=None):
        """
        Get work for remote mining, or submit result.
        If data is specified, the server tries to solve the block
        using the provided data and returns :const:`True` if it was successful.
        If not, the function returns formatted hash data (:class:`~bitcoinrpc.data.WorkItem`)
        to work on.
        Arguments:
        - *data* -- Result from remote mining.
        """
        if data is None:
            # Only if no data provided, it returns a WorkItem
            return WorkItem(**self.proxy.getwork())
        else:
            return self.proxy.getwork(data)

    def listunspent(self, minconf=1, maxconf=999999):
        """
        Returns a list of unspent transaction inputs in the wallet.
        Arguments:
        - *minconf* -- Minimum number of confirmations required to be listed.
        - *maxconf* -- Maximal number of confirmations allowed to be listed.
        """
        return [TransactionInfo(**tx) for tx in
                self.proxy.listunspent(minconf, maxconf)]

    def keypoolrefill(self):
        "Fills the keypool, requires wallet passphrase to be set."
        self.proxy.keypoolrefill()

    def walletpassphrase(self, passphrase, timeout, dont_raise=False):
        """
        Stores the wallet decryption key in memory for <timeout> seconds.
        - *passphrase* -- The wallet passphrase.
        - *timeout* -- Time in seconds to keep the wallet unlocked
                       (by keeping the passphrase in memory).
        - *dont_raise* -- instead of raising `~bitcoinrpc.exceptions.WalletPassphraseIncorrect`
                          return False.
        """
        try:
            self.proxy.walletpassphrase(passphrase, timeout)
            return True
        except BitcoinException as exception:
            if dont_raise:
                if isinstance(exception, WalletPassphraseIncorrect):
                    return False
                elif isinstance(exception, WalletAlreadyUnlocked):
                    return True
            raise exception

    def walletlock(self):
        """
        Removes the wallet encryption key from memory, locking the wallet.
        After calling this method, you will need to call walletpassphrase
        again before being able to call any methods which require the wallet
        to be unlocked.
        """
        return self.proxy.walletlock()

    def walletpassphrasechange(self, oldpassphrase, newpassphrase, dont_raise=False):
        """
        Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.
        Arguments:
        - *dont_raise* -- instead of raising `~bitcoinrpc.exceptions.WalletPassphraseIncorrect`
                          return False.
        """
        try:
            self.proxy.walletpassphrasechange(oldpassphrase, newpassphrase)
            return True
        except BitcoinException as exception:
            if dont_raise and isinstance(exception, WalletPassphraseIncorrect):
                return False
            raise exception

    def dumpprivkey(self, address):
        """
        Returns the private key belonging to <address>.
        Arguments:
        - *address* -- Bitcoin address whose private key should be returned.
        """
        return self.proxy.dumpprivkey(address)

    def signmessage(self, address, message):
        """
        Sign messages, returns the signature
        :param address: Bitcoin address used to sign a message
        :type address: str or unicode
        :param message: The message to sign
        :type message: str or unicode
        :rtype: unicode
        """
        return self.proxy.signmessage(address, message)

    def verifymessage(self, address, signature, message):
        """
        Verify a signed message
        :param address: Bitcoin address used to sign a message
        :type address: str or unicode
        :param signature: The signature
        :type signature: unicode
        :param message: The message to sign
        :type message: str or unicode
        :rtype: bool
        """
        return self.proxy.verifymessage(address, signature, message)


# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
# //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

import binascii
import time
from datetime import date
import sys

import os
from os import path
import array
import collections

import csv
import math
import struct
import random


import operator

DEF_CONN_USER = 'hdacrpc'
DEF_CONN_PWD = 'CqcMpd2He9Wj4KNoJUEBAfyF2i61FjJyLRBFWB7hPmgZ'
DEF_CONN_HOST = '192.168.70.234'
DEF_CONN_PORT = 8822
DEF_CONN_HTTPS = False




#DEF_DB_FILE_RAW = 'raw.csv'
#DEF_DB_FILE_RAW = 'hdactest_135.csv'
#DEF_DB_FILE_RAW = 'hdactest_5xxx.csv'
#DEF_DB_FILE_RAW = 'hdactest_all.csv'
DEF_DB_FILE_RAW = 'hdac_main.csv'

DEF_DB_FILE_MAINSTAT = 'mainstat.csv'
DEF_DB_FILE_STAT480B = 'stat480B.csv'
DEF_DB_FILE_STAT_MAXP = 'stat20P.csv'
DEF_DB_FILE_STAT_MINP = 'stat5P.csv'
DEF_DB_FILE_STAT_MINERLIST = 'minerlist.csv'
DEF_DB_FILE_STAT_MINERSTAT = 'minerstat.csv'
DEF_DB_FILE_STAT_MINERSTAT_SUB_GRP = 'minerstat_subgrp.csv'
DEF_DB_FILE_STAT_MINERSTAT_SUB_FGI = 'minerstat_subfgi.csv'
DEF_DB_FILE_STAT_MINERSTAT_SUB_ACI = 'minerstat_subaci.csv'

#ref_file
DEF_DB_FILE_MINER_REF_GRP_DEF = 'ref/group_def.csv'
DEF_DB_FILE_MINER_REF_FD_TO_FI = 'ref/fd_to_fi.csv'
DEF_DB_FILE_MINER_REF_FI_TO_FGI = 'ref/fi_to_grpfg.csv'
DEF_DB_FILE_MINER_REF_FI_TO_ACI = 'ref/fi_to_grpac.csv'

DEF_DB_FILE_HEADSTART = 'bIndex'

DEF_DB_STAT_CONSTANT_MEMORY_MIN = 960
DEF_DB_STAT_CONSTANT_MEMORY_MAX = 960

DEF_DB_MIN_STAT_NUM = 480
DEF_DB_STAT_CONSTANT_BRTIME = 180
DEF_DB_STAT_CONSTANT_BO = 3600

DEF_DB_STAT_SAMPLE_MIN_PERIODE = 5
DEF_DB_STAT_SAMPLE_MAX_PERIODE = 20

DEF_DB_MIN_STAT_CHECK_MID = 120
DEF_DB_MIN_STAT_CHECK_MAX = DEF_DB_MIN_STAT_NUM

DEF_DB_MINER_STAT_CHECK_PERIODE = DEF_DB_STAT_SAMPLE_MAX_PERIODE

def removeFiles(fname):
    fp = open(fname, 'w')
    fp.close()

def AddToFiles(fname,info):
    fp = open(fname, 'a')
    t_str = "%s\n" % (info)
    fp.write(t_str)
    fp.close()


DEF_DB_RAW_DICT = collections.OrderedDict([(DEF_DB_FILE_HEADSTART,0),('nTime',0),('nBits',''),('Nonce',0),('Chainworks',0),('Difficulty',0.),('MinerAD',''),('CoinAD',''),('nTxs',0),('BSize',0)])
DEF_DB_MAINSTAT_DICT = collections.OrderedDict([(DEF_DB_FILE_HEADSTART,0),('Localtime',''),('nBits',''),('Chainworks',0),('MinerAD',''),('CoinAD',''),('nTime',0),('nTxs',0),('DiffIndex',0),('NF',0),('DIFF',0.),('bTime',0),('bTime120',0.),('bTime480',0.),('BO',0),('BR',0.),('BR120',0.),('BR480',0.),('HPS',0),('HPS120',0),('HPS480',0),('TPS',0.),('TPS120',0.),('TPS480',0.)])
DEF_DB_480B_DICT = collections.OrderedDict([(DEF_DB_FILE_HEADSTART,0),('bIndexEnd',0),('elapsedBI',0),('DiffIndex',0),('Difficulty',0.),('StartTime',''),('EndTime',''),('StartTimeLocal',''),('EndTimeLocal',''),('elapsedTime',0), ('bTime480',0.),('BO',0),('BR480',0.),('HPS480',0)])
DEF_DB_SAMPLE_DICT = collections.OrderedDict([(DEF_DB_FILE_HEADSTART,0),('Localtime',''),('nBits',''),('Chainworks',0),('MinerAD',''),('CoinAD',''),('nTime',0),('nTxs',0),('DiffIndex',0),('NF',0),('DIFF',0.),('bTime',0),('bTime120',0.),('bTime480',0.),('BO',0),('BR',0.),('BR120',0.),('BR480',0.),('HPS',0),('HPS120',0),('HPS480',0),('TPS',0.),('TPS120',0.),('TPS480',0.)])

DEF_DB_MINERLIST_DICT = collections.OrderedDict([(DEF_DB_FILE_HEADSTART,0),('MinerAD',''),('CoinAD','')])
DEF_DB_MINERSTAT_DICT = collections.OrderedDict([('MinerAD',''),('ETC',''),('GRP_AD',''),('GRP_FGI',''),('GRP_ACI',''),('1st',0),('2nd',0),('3rd',0),('4th',0),('5th',0),('6th',0),('7th',0),('8th',0),('9th',0),('10th',0),('11th',0),('12th',0),('13th',0),('14th',0),('15th',0),('16th',0),('17th',0),('18th',0),('19th',0),('20th',0),('Total',0),('1stP',0),('2ndP',0),('3rdP',0),('4thP',0),('5thP',0),('6thP',0),('7thP',0),('8thP',0),('9thP',0),('10thP',0),('11thP',0),('12thP',0),('13thP',0),('14thP',0),('15thP',0),('16thP',0),('17thP',0),('18thP',0),('19thP',0),('20thP',0),('TotalP',0),])
DEF_DB_MINERSTAT_SUB_GRP_DICT = collections.OrderedDict([('GRP_AD',''),('1st',0),('2nd',0),('3rd',0),('4th',0),('5th',0),('6th',0),('7th',0),('8th',0),('9th',0),('10th',0),('11th',0),('12th',0),('13th',0),('14th',0),('15th',0),('16th',0),('17th',0),('18th',0),('19th',0),('20th',0),('Total',0),('1stP',0),('2ndP',0),('3rdP',0),('4thP',0),('5thP',0),('6thP',0),('7thP',0),('8thP',0),('9thP',0),('10thP',0),('11thP',0),('12thP',0),('13thP',0),('14thP',0),('15thP',0),('16thP',0),('17thP',0),('18thP',0),('19thP',0),('20thP',0),('TotalP',0),])
DEF_DB_MINERSTAT_SUB_FGI_DICT = collections.OrderedDict([('GRP_FGI',''),('1st',0),('2nd',0),('3rd',0),('4th',0),('5th',0),('6th',0),('7th',0),('8th',0),('9th',0),('10th',0),('11th',0),('12th',0),('13th',0),('14th',0),('15th',0),('16th',0),('17th',0),('18th',0),('19th',0),('20th',0),('Total',0),('1stP',0),('2ndP',0),('3rdP',0),('4thP',0),('5thP',0),('6thP',0),('7thP',0),('8thP',0),('9thP',0),('10thP',0),('11thP',0),('12thP',0),('13thP',0),('14thP',0),('15thP',0),('16thP',0),('17thP',0),('18thP',0),('19thP',0),('20thP',0),('TotalP',0),])
DEF_DB_MINERSTAT_SUB_ACI_DICT = collections.OrderedDict([('GRP_ACI',''),('1st',0),('2nd',0),('3rd',0),('4th',0),('5th',0),('6th',0),('7th',0),('8th',0),('9th',0),('10th',0),('11th',0),('12th',0),('13th',0),('14th',0),('15th',0),('16th',0),('17th',0),('18th',0),('19th',0),('20th',0),('Total',0),('1stP',0),('2ndP',0),('3rdP',0),('4thP',0),('5thP',0),('6thP',0),('7thP',0),('8thP',0),('9thP',0),('10thP',0),('11thP',0),('12thP',0),('13thP',0),('14thP',0),('15thP',0),('16thP',0),('17thP',0),('18thP',0),('19thP',0),('20thP',0),('TotalP',0),])


DEF_DB_REF_GRP_AD_DICT = collections.OrderedDict([('ADDR',''),('GRP_AD',''),('FEEDTO',''),('ETC',''),])
DEF_DB_REF_FEED_TO_FI_DICT = collections.OrderedDict([('FEEDTO',''),('FI','')])
DEF_DB_REF_FI_TO_FGI_DICT = collections.OrderedDict([('FI',''),('FGI','')])
DEF_DB_REF_FI_TO_GRPACI_DICT = collections.OrderedDict([('FI',''),('GRP_ACI','')])


MinerStatkeyList = ['1st', '2nd', '3rd', '4th', '5th', '6th', '7th', '8th', '9th', '10th', '11th', '12th', '13th', '14th', '15th', '16th', '17th', '18th', '19th', '20th']
MinerStatkeyListSecond = ['1stP', '2ndP', '3rdP', '4thP', '5thP', '6thP', '7thP', '8thP', '9thP', '10thP', '11thP', '12thP', '13thP', '14thP', '15thP', '16thP', '17thP', '18thP', '19thP', '20thP']
                        
# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////
class MyChainDatabase():
    def __init__(self):
        self.tip_height = -1
        self.raw_start_index = -1
        self.raw_db_count = 0
        self.raw_db_height = -1
        self.connected = False
        self.objConn = None
        self.calcDbCount = 0
        self.calcDB = []

    # ///////////////////////////////////////////////////////////////////////
    
    def read_csv(self, fname="", load=False):
        if(fname==""):
            return
        
        num  = 0
        """
        with open(fname, 'r') as raw:
            wrapper = csv.reader(raw)
            for record in wrapper:
                if record:
                    items = []*3
                    items.append(record[0])
                    items.append(record[1])
                    items.append(float(record[2]))
                    
                    num += 1
                    
                    if load :
                        self.fileListMiner.append(items)
                        self.fileListMinerCount = num
        
        """
        return num
    
    # ///////////////////////////////////////////////////////////////////////
    
    def loadcsv(self, fname):
        numItems = 0
        numItems = self.read_csv(fname, False)
        
        if (numItems < 1):
            return False
        """
        numItems = self.read_csv(fname, True)
        
        newList = [] * numItems
        
        #set random hps, unit 1000
        # 0.1 ~ 10 T
        # 1 ~ 100, and multiply with 100
        # max -1 : just one
        # max  5% = just one
        # max  10% just
        
        for i in range(numItems):
            tList = []
            tList.append(self.fileListMiner[i][0])
            tList.append(self.fileListMiner[i][1])
            tList.append(self.fileListMiner[i][2]*DEF_GHPS_MULTIPLY)
            #tNum = random.randrange(DEF_TEST_HPS_MIM,DEF_TEST_HPS_MAX)
            #tNum *= DEF_GHPS_MULTIPLY
            #tList.append(tNum)
            newList.append(tList)
        
        self.fileListMiner = []
        self.fileListMinerCount = 0
        
        self.fileListMiner = newList
        self.fileListMinerCount = len(self.fileListMiner)
        """
        return True
    
    # ///////////////////////////////////////////////////////////////////////
    
    def saveWithJson(self, data):
        with open(DEF_DB_FILE_RAW, 'a') as fp:
            json.dump(data, fp)
    
    # ///////////////////////////////////////////////////////////////////////
    
    def loadWithJson(self):
        with open(DEF_DB_FILE_RAW) as fp:
            data = json.load(fp)
            return data
        return None    
     
    # ///////////////////////////////////////////////////////////////////////
    
    def getConnection(self):
        self.objConn = BitcoinConnection(DEF_CONN_USER,DEF_CONN_PWD,DEF_CONN_HOST,DEF_CONN_PORT,DEF_CONN_HTTPS)
        self.connected = True

    # ///////////////////////////////////////////////////////////////////////
    
    def IsConnected(self):
        if self.objConn is None:
            return False
        elif not self.connected:
            print "[ERROR] Not Connected"
            return Falseo9
        return True

    # ///////////////////////////////////////////////////////////////////////
    
    def checkConnection(self): 
        if not self.IsConnected():
            self.getConnection()
        
        return self.IsConnected()

    # ///////////////////////////////////////////////////////////////////////
    
    def GetInfo(self):
        if not self.checkConnection():
            return None
        
        return self.objConn.getinfo()

    # ///////////////////////////////////////////////////////////////////////
        
    def GetBlock(self, hashtype=False, index=None, grade=0):
        if not self.checkConnection():
            return None
        
        info = None
        
        if(hashtype):
            if(len(index)<32):
                print "[ERROR] Abnormal hash length : %d" % len(index)
                return None
            else:
                info = index
        else:
            if(index>=0):
                info = "%d" % index
            else:
                print "[ERROR] Abnormal index : %d" % index
                return None        
          
        objinfo =  self.objConn.getblockwithlevel(info,grade)        
        
        return objinfo
 
    # ////////////////////////////////////////////////////////////////////////
    
    def GetCoinBaseAddress(self, tx):
        if tx is None:
            return None
        
        txlen = len(tx['vout'])
        address = ''
        if(txlen>0):
            addrlen = len(tx['vout'][0]['scriptPubKey']['addresses'])
            if(addrlen>0):
                address = tx['vout'][0]['scriptPubKey']['addresses'][0]
        return address
    
    # ///////////////////////////////////////////////////////////////////////
    
    def SaveDictToFiles(self,fname='',objDict=None):            
        myDictKeys = objDict.keys()
        myFInfo = ''
        for i in myDictKeys:
            if (isinstance(objDict[i], float)):
                myFInfo += "%.3f," % objDict[i]
            elif (isinstance(objDict[i], int)):
                myFInfo += "%d," % objDict[i]
            else:
                myFInfo += "%s," % objDict[i]
        
        AddToFiles(fname,myFInfo)        
        
    # ///////////////////////////////////////////////////////////////////////

    def CheckDBIndex(self, bRaw=False, fName=''):
        lastIndex = -1
        NewIndex = 0
        bStatus = False
        countDB = 0
        startIndex = -1
        
        if bRaw:
            self.raw_start_index = -1
            self.raw_db_count = 0
            self.raw_db_height = -1
            startIndex = -1
            countDB = 0
        
        if not (path.exists(fName)):
            print "[ERROR] CheckDBIndex : Not Exist : %s" % fName
            return -1
        
        print "[CheckDBIndex] : fName = %s, bRaw = %d" % (fName, bRaw)
        
        with open(fName, 'r') as raw:
            wrapper = csv.reader(raw) 
            bStatus = True
            bcheckHead = False
            
            for record in wrapper:
                if record and bStatus:
                    if bcheckHead:
                        NewIndex = int(record[0])
                        if bRaw:
                            countDB += 1
                            if (startIndex<0):
                                startIndex = NewIndex
                                                        
                        if (NewIndex>=0):
                            if(NewIndex>lastIndex):
                                lastIndex = NewIndex
                            else:
                                print "[ERROR] [CheckDBIndex] there is index mismatch : lastIndex=%d NewIndex=%d" % (lastIndex, NewIndex)
                                bStatus = False
                        else:
                            print "[ERROR] [CheckDBIndex] there is index mismatch : lastIndex=%d NewIndex=%d" % (lastIndex, NewIndex)
                            bStatus = False
                    else:
                        bcheckHead = True
                        tempHead = record[0]
                        if(tempHead != DEF_DB_FILE_HEADSTART):
                            print "[ERROR] CheckDBIndex : invalid head start type : %s" % (tempHead)
                            bStatus = False
 
        if bStatus:
            if bRaw:
                self.raw_start_index = startIndex
                self.raw_db_count = countDB
                self.raw_db_height = lastIndex
                print "[CheckDBIndex] %d ~ %d checked. with count=%d" % (startIndex, lastIndex, countDB)
            else:
                print "[CheckDBIndex] latest index=%d " % (lastIndex)
            
            return lastIndex
        else:
            if bRaw:
                self.raw_db_start = -1
                self.raw_db_count = 0
                self.raw_db_height = -1                
            print "[ERROR] [CheckDBIndex] something wrong !!! [%s]" % (fName)
            return -1    
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckGroupAD(self, tValue=''):
        bStatus = True
        bFound = False
        bCont = True
        bcheckHead = False
        
        fName = DEF_DB_FILE_MINER_REF_GRP_DEF
        tDict = DEF_DB_REF_GRP_AD_DICT
        tDict['ADDR'] = tValue
        tDict['GRP_AD'] = 'None'
        tDict['FEEDTO'] = ''
        tDict['ETC'] = ''
        
        if not (path.exists(fName)):
            print "[ERROR] CheckGroupAD : Not Exist : %s" % fName
            return tDict
        
        with open(fName, 'r') as raw:
            wrapper = csv.reader(raw) 
            for record in wrapper:
                if record and bStatus and bCont:
                    if bcheckHead:
                        newValue = record[0]
                        if(newValue==tValue):
                            # (ADDR,''),(GRP_AD,''),(FEEDTO,''),(ETC,''),])
                            tDict['ADDR'] = record[0]
                            tDict['GRP_AD'] = record[1]
                            tDict['FEEDTO'] = record[2]
                            tDict['ETC'] = record[3]
                            bFound = True
                            bCont = False
                    else:
                        bcheckHead = True
                        tempHead = record[0]
                        if(tempHead == 'ADDR'):
                            continue
                        else:
                            print "[ERROR] CheckGroupAD : invalid head start type : %s" % (tempHead)
                            bStatus = False
 
        return tDict 
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckFI(self, tValue=''):
        bStatus = True
        bFound = False
        bCont = True
        bcheckHead = False
        
        fName = DEF_DB_FILE_MINER_REF_FD_TO_FI
        tDict = DEF_DB_REF_FEED_TO_FI_DICT
        tDict['FEEDTO'] = tValue
        tDict['FI'] = 'None'
        
        if not (path.exists(fName)):
            print "[ERROR] CheckFI : Not Exist : %s" % fName
            return tDict
        
        with open(fName, 'r') as raw:
            wrapper = csv.reader(raw) 
            for record in wrapper:
                if record and bStatus and bCont:
                    if bcheckHead:
                        newValue = record[0]
                        if(newValue==tValue):
                            # (FEEDTO,''),(FI,'')
                            tDict['FEEDTO'] = record[0]
                            tDict['FI'] = record[1]
                            bFound = True
                            bCont = False
                    else:
                        bcheckHead = True
                        tempHead = record[0]
                        if(tempHead == 'FEEDTO'):
                            continue
                        else:
                            print "[ERROR] CheckFI : invalid head start type : %s" % (tempHead)
                            bStatus = False
 
        return tDict 
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckFGI(self, tValue=''):
        bStatus = True
        bFound = False
        bCont = True
        bcheckHead = False
        
        fName = DEF_DB_FILE_MINER_REF_FI_TO_FGI
        tDict = DEF_DB_REF_FI_TO_FGI_DICT
        tDict['FI'] = tValue
        tDict['FGI'] = 'None'
        
        if not (path.exists(fName)):
            print "[ERROR] CheckFGI : Not Exist : %s" % fName
            return tDict
        
        with open(fName, 'r') as raw:
            wrapper = csv.reader(raw) 
            for record in wrapper:
                if record and bStatus and bCont:
                    if bcheckHead:
                        newValue = record[0]
                        if(newValue==tValue):
                            # (FI,''),(FGI,'')
                            tDict['FI'] = record[0]
                            tDict['FGI'] = record[1]
                            bFound = True
                            bCont = False
                    else:
                        bcheckHead = True
                        tempHead = record[0]
                        if(tempHead == 'FI'):
                            continue
                        else:
                            print "[ERROR] CheckFGI : invalid head start type : %s" % (tempHead)
                            bStatus = False
 
        return tDict 
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckGrpAci(self, tValue=''):
        bStatus = True
        bFound = False
        bCont = True
        bcheckHead = False
        
        fName = DEF_DB_FILE_MINER_REF_FI_TO_ACI
        tDict = DEF_DB_REF_FI_TO_GRPACI_DICT
        tDict['FI'] = tValue
        tDict['GRP_ACI'] = 'None'
        
        if not (path.exists(fName)):
            print "[ERROR] CheckGrpAci : Not Exist : %s" % fName
            return tDict
        
        with open(fName, 'r') as raw:
            wrapper = csv.reader(raw) 
            for record in wrapper:
                if record and bStatus and bCont:
                    if bcheckHead:
                        newValue = record[0]
                        if(newValue==tValue):
                            # (FI,''),(GRP_ACI,'')
                            tDict['FI'] = record[0]
                            tDict['GRP_ACI'] = record[1]
                            bFound = True
                            bCont = False
                    else:
                        bcheckHead = True
                        tempHead = record[0]
                        if(tempHead == 'FI'):
                            continue
                        else:
                            print "[ERROR] CheckGrpAci : invalid head start type : %s" % (tempHead)
                            bStatus = False
 
        return tDict 
    
    # ///////////////////////////////////////////////////////////////////////
    
    
    # ///////////////////////////////////////////////////////////////////////
    
    
    
    
    
    # ///////////////////////////////////////////////////////////////////////
    
    # ///////////////////////////////////////////////////////////////////////

    
    
    # ///////////////////////////////////////////////////////////////////////
    
    # ///////////////////////////////////////////////////////////////////////
    
    def MakeRawDB(self, bNew=False, startI=0, EndI=0):
        if bNew:
            removeFiles(DEF_DB_FILE_RAW)
            headerString = ''
            for i in DEF_DB_RAW_DICT.keys():
                headerString += (i + ',')
            AddToFiles(DEF_DB_FILE_RAW,headerString)    
        
        ticks = time.time()
        origRawCount = self.raw_db_count
        lastestIndex = -1
        dbCount = EndI - startI
        dbDispStep = 1
        dbStep = 0
        
        if(dbCount>100):
            dbDispStep = 50
        elif(dbCount>10):
            dbDispStep = 10
        
        for i in range(startI,EndI):
            blockInfo = self.GetBlock(False, i, 4)
            coinTxAddr = ''
            if blockInfo is None:
                print "[ERROR] MakeRawDB : GetBlock : %d" % i
            else:
                txsize = len(blockInfo['tx'])
                if(txsize>0):
                    address = self.GetCoinBaseAddress(blockInfo['tx'][0])
                
                chainwork = long(blockInfo['chainwork'], 16)
                
                tDict = DEF_DB_RAW_DICT
                tDict[DEF_DB_FILE_HEADSTART] = blockInfo['height']
                tDict['nTime'] = blockInfo['time']
                tDict['nBits'] = blockInfo['bits']
                tDict['Nonce'] = blockInfo['nonce']
                tDict['Chainworks'] = chainwork
                tDict['Difficulty'] = blockInfo['difficulty']
                tDict['MinerAD'] = blockInfo['miner']
                tDict['CoinAD'] = address
                tDict['nTxs'] = txsize
                tDict['BSize'] = blockInfo['size']
                
                self.SaveDictToFiles(DEF_DB_FILE_RAW,tDict)                
                #AddToFiles(DEF_DB_FILE_RAW, "%d,%d,%s,%d,%d,%.8f,%s,%s,%d,%d" % (blockInfo['height'], blockInfo['time'], blockInfo['bits'], blockInfo['nonce'], chainwork, blockInfo['difficulty'], blockInfo['miner'], address, txsize, blockInfo['size']))
                
                lastestIndex = i
                origRawCount += 1
                dbStep += 1
                
                if ((dbStep%dbDispStep)==0) or (dbStep==dbCount):
                    print "[MakeRawDB] current Height : %d[%.2f%%]" % (i,dbStep*100/dbCount)
        
        self.raw_db_count = origRawCount
        self.raw_db_height = lastestIndex
        
        ticks2 = time.time()
        print "[MakeRawDB] %d seconds elapsed !! " % (ticks2-ticks)
        print "[MakeRawDB] Raw db updated with height:%d[dbcount=%d]" % (lastestIndex, origRawCount)
        
    # ///////////////////////////////////////////////////////////////////////

    def SyncChainWithRawDB(self, bOffline=False):
        bStatus = True
        
        UptStartIndex = 0
        UptEndIndex = 0
        
        if not bOffline:
            objinfo = self.GetInfo()
            if objinfo is None:
                print "[ERROR] SyncChainWithRawDB : None : Getinfo"
                return False
        
            if(objinfo['blocks']<0):
                print "[ERROR] SyncChainWithRawDB : Obious info : Getinfo"
                return False
        
            self.tip_height =  objinfo['blocks']        
            print "[SyncChainWithRawDB] Latest Height : %d" % self.tip_height
        
            UptStartIndex = 0
            UptEndIndex = self.tip_height
        
        checkRawIndex = 0
        if (path.exists(DEF_DB_FILE_RAW)):
            checkRawIndex = self.CheckDBIndex(True, DEF_DB_FILE_RAW)
        else:
            headerString = ''
            for i in DEF_DB_RAW_DICT.keys():
                headerString += (i + ',')
            AddToFiles(DEF_DB_FILE_RAW,headerString)
        
        if(checkRawIndex<0):
            print "[ERROR] SyncChainWithRawDB : check DB : checkRawIndex = %d" % (checkRawIndex)
            return False
        else:
            UptStartIndex = checkRawIndex
        
        if bOffline:
            self.tip_height= UptStartIndex
            UptEndIndex = UptStartIndex
        
        if (UptStartIndex < UptEndIndex):
            print "[SyncChainWithRawDB] Make Raw DB : %d ~ %d" % (UptStartIndex,UptEndIndex)
            self.MakeRawDB(False,UptStartIndex+1,UptEndIndex+1)
        elif(UptStartIndex > UptEndIndex):
            print "[ERROR] SyncChainWithRawDB : check DB : %d vs %s" % (UptStartIndex,UptEndIndex)
            bStatus = False
        else:
            print "[SyncChainWithRawDB] Sync OK"
        
        return bStatus
    
    # ///////////////////////////////////////////////////////////////////////
    
    def LoadDB(self, fname='', tDict=None, startI=0, needCntDB = 0, bCopyMain = False, fnameTarget='', ):
        #ticks = time.time()
        
        if not bCopyMain:
            self.calcDB = []
        
        countDB = 0
        endI = 0
        
        print "[LoadDB][%s] from %d with %d" % (fname,startI,needCntDB)
        
        with open(fname, 'r') as raw:
            wrapper = csv.reader(raw) 
            bStatus = True 
            bCont = True
            bSkipHead=False
            
            for record in wrapper:
                if record and bStatus and bCont:
                    if bSkipHead:
                        NewIndex = int(record[0])                    
                        if(NewIndex >= startI):
                            step = 0                            
                            for i in tDict.keys():
                                if (isinstance(tDict[i], float)):
                                    tDict[i] = float(record[step])
                                elif (isinstance(tDict[i], long)):
                                    tDict[i] = long(record[step])
                                elif (isinstance(tDict[i], int)):
                                    tDict[i] = int(record[step])
                                else:
                                    tDict[i] = record[step]
                                step += 1
                            
                            countDB += 1
                            if not bCopyMain:
                                self.calcDB.append(tDict.copy())
                                if(countDB>=needCntDB):
                                    endI = NewIndex
                                    bCont = False
                                    break
                            else:
                                endI = NewIndex
                                self.SaveDictToFiles(fnameTarget,tDict)
                            
                    else:
                        bSkipHead = True
                        tempHead = record[0]
                        if(tempHead == DEF_DB_FILE_HEADSTART):
                            continue
                        else:
                            print "[ERROR][%s] LoadDB : invalid head start type : %s" % (fname, tempHead)
                            bStatus = False
        
        #ticks2 = time.time()
        #print "[MAKEDB] %d seconds elapsed !! " % (ticks2-ticks)
        
        if not bStatus:
            print "[ERROR]LoadDB : something worrong : %s" % (fname)
            return -1
        
        if(countDB>0):
            if not bCopyMain:
                self.calcDbCount = countDB
                print "[LoadDB][%s] %d items loaded [%d ~ %d]" % (fname, self.calcDbCount, startI, endI)
            return countDB
        else:
            print "[LoadDB][%s] Failure in Load Raw DB " % (fname)
            if not bCopyMain:
                self.calcDbCount = 0
                self.calcDB = []
                return 0
            else:
                return -1
           
    # ///////////////////////////////////////////////////////////////////////
    
    def LoadDBwithDict(self, fname='', tDictOrig=None, tDictNew=None, startI=0, needCntDB = 0, bSkipHead=False):
        #ticks = time.time()
        
        self.calcDB = []        
        countDB = 0
        endI = 0
        
        print "[LoadDB][%s] from %d with %d" % (fname,startI,needCntDB)
        
        with open(fname, 'r') as raw:
            wrapper = csv.reader(raw) 
            bStatus = True 
            bCont = True          
            for record in wrapper:
                if record and bStatus and bCont:
                    if bSkipHead:
                        NewIndex = int(record[0])                    
                        if(NewIndex >= startI):
                            step = 0                            
                            for i in tDictOrig.keys():
                                if (isinstance(tDictOrig[i], float)):
                                    tDictOrig[i] = float(record[step])
                                elif (isinstance(tDictOrig[i], int)):
                                    tDictOrig[i] = int(record[step])
                                else:
                                    tDictOrig[i] = record[step]
                                step += 1
                            
                            for i in tDictNew.keys():
                                for j in tDictOrig.keys():
                                    if(i==j):
                                        tDictNew[i] = tDictOrig[j]
                                        break
                            
                            countDB += 1
                            self.calcDB.append(tDictNew.copy())
                            if(countDB>=needCntDB):
                                endI = NewIndex
                                bCont = False
                                break
                            
                    else:
                        bSkipHead = True
                        tempHead = record[0]
                        if(tempHead != DEF_DB_FILE_HEADSTART):
                            print "[ERROR][%s] LoadDBwithDict : invalid head start type : %s" % (fname, tempHead)
                            bStatus = False
        
        #ticks2 = time.time()
        #print "[LoadDBwithDict] %d seconds elapsed !! " % (ticks2-ticks)
        
        if not bStatus:
            return -1
        
        if(countDB>0):
            self.calcDbCount = countDB
            print "[LoadDBwithDict][%s] %d items loaded [%d ~ %d]" % (fname, self.calcDbCount, startI, endI)
            return countDB
        else:
            print "[LoadDBwithDict][%s] Failure in Load Raw DB " % (fname)
            return -1
           
    # ///////////////////////////////////////////////////////////////////////
    
    def LoadMainStatDBAndCopy(self, fnameLoad='', startI=0, fnameTarget='', bSkipHead=False):
        #ticks = time.time()  
        countDB = 0
        endI = 0
        
        with open(fnameLoad, 'r') as raw:
            wrapper = csv.reader(raw) 
            bStatus = True 
            bCont = True          
            for record in wrapper:
                if record and bStatus and bCont:
                    if bSkipHead:
                        NewIndex = int(record[0])                    
                        if(NewIndex >= startI):
                            step = 0
                            tDict = None
                            tDict = DEF_DB_MAINSTAT_DICT
                            for i in DEF_DB_MAINSTAT_DICT.keys():
                                if (isinstance(tDict[i], float)):
                                    tDict[i] = float(record[step])
                                elif (isinstance(tDict[i], int)):
                                    tDict[i] = int(record[step])
                                else:
                                    tDict[i] = record[step]
                                step += 1
                            
                            self.SaveDictToFiles(fnameTarget,tDict)
                            countDB += 1
                            endI = NewIndex
                    else:
                        bSkipHead = True
                        tempHead = record[0]
                        if(tempHead != DEF_DB_FILE_HEADSTART):
                            print "[ERROR][%s] LoadMainStatDBAndCopy : invalid head start type : %s" % (fname, tempHead)
                            bStatus = False
        
        #ticks2 = time.time()
        #print "[LoadMainStatDBAndCopy] %d seconds elapsed !! " % (ticks2-ticks)
        
        if not bStatus:
            return -1
        
        if(countDB>0):
            print "[LoadMainStatDBAndCopy][%s] %d items loaded [%d ~ %d]" % (fnameTarget, countDB, startI, endI)
            return countDB
        else:
            print "[LoadMainStatDBAndCopy][%s] Failure in get DB " % (fnameLoad)
            return -1
           
    
    # ///////////////////////////////////////////////////////////////////////
   
    
    
    
    
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getNF(self, dbIndex=0, key='', objDB=None):
        if (dbIndex<1):
            return 0
        
        listNF = []
        startI = dbIndex - DEF_DB_MIN_STAT_NUM
        if(startI<0):
            startI = 0
        
        for i in range(startI, dbIndex):
            tDup = listNF.count(objDB[i][key])
            if (tDup<1):
                listNF.append(objDB[i][key])
        
        return len(listNF)
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getAvrInfoInMainStat(self, dbIndex=0, key='', rangeIndex=1, objDB=None):
        if (dbIndex<0) or (rangeIndex<1) or (rangeIndex>480):
            return 1
        
        if (dbIndex==0):
            tInfo = objDB[dbIndex][key]
            return tInfo
        
        startI = dbIndex - rangeIndex + 1
        if(startI<0):
            startI = 0
            rangeIndex = dbIndex - startI + 1
        
        if(rangeIndex<1):
            return 0
        
        tInfo = 0.
        for i in range(startI, dbIndex+1):
            tInfo += objDB[i][key]
        
        tInfo /= float(rangeIndex)
        return tInfo
    
    # ///////////////////////////////////////////////////////////////////////
    
    def startGetMainStat(self, countLoaded, indexMainStatEnd, oldcount):
        if (countLoaded<1) or (indexMainStatEnd<0) or (oldcount<0) or (oldcount>DEF_DB_MIN_STAT_NUM):
            return -1
            
        if (countLoaded != self.calcDbCount):
            print "[ERROR] startGetMainStat : loaded info mismatch: countLoaded=%d vs self.calcDbCount=%d" % (countLoaded, self.calcDbCount)
            return -1
        
        targetCount = countLoaded - oldcount
        
        tCount120 = 0
        tCount480 = 0
        
        countStat = 0
        
        for i in range(1,countLoaded):
            # nTime nBits Nonce Chainworks Difficulty MinerAD CoinAD nTxs BSize 
            # nBits Chainworks MinerAD CoinAD nTime nTxs Localtime DiffIndex NF DIFF bTime bTime120 bTime480 BO BR BR120 BR480 HPS HPS120 HPS480 TPS TPS120 TPS480
            
            tIndex = self.calcDB[i][DEF_DB_FILE_HEADSTART]
            # check add or not
            if(tIndex<=indexMainStatEnd):
                continue
                
            tDB = DEF_DB_MAINSTAT_DICT
            
            # bIndex
            tDB[DEF_DB_FILE_HEADSTART] = tIndex
            
            if(i>=DEF_DB_MIN_STAT_CHECK_MAX):
                tCount120 = DEF_DB_MIN_STAT_CHECK_MID
                tCount480 = DEF_DB_MIN_STAT_CHECK_MAX
            elif(i>=DEF_DB_MIN_STAT_CHECK_MID):
                tCount120 = DEF_DB_MIN_STAT_CHECK_MID
                tCount480 = i
            else:
                tCount120 = i
                tCount480 = i
                
            tDB['MinerAD'] = self.calcDB[i]['MinerAD']
            tDB['CoinAD'] = self.calcDB[i]['CoinAD']
            tDB['nBits'] = self.calcDB[i]['nBits']
            tDB['nTime'] = self.calcDB[i]['nTime']
            tDB['Localtime'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.calcDB[i]['nTime']))
            
            tDiffIndex = tIndex / DEF_DB_MIN_STAT_NUM
            tDiffIndex += 1
            tDB['DiffIndex'] = tDiffIndex
            tDB['DIFF'] = self.calcDB[i]['Difficulty']
            tDB['NF'] = self.getNF(i,'MinerAD',self.calcDB)
            
            tTime = self.calcDB[i]['nTime'] - self.calcDB[i-1]['nTime']
            if (tTime<1):
                tTime = 1
            
            tDB['bTime'] = tTime
            if(tTime>=DEF_DB_STAT_CONSTANT_BO):
                tDB['BO'] = 1
            else:
                tDB['BO'] = 0 
            
            tDiffTime120 = self.calcDB[i]['nTime'] - self.calcDB[i-tCount120]['nTime']
            tDiffTime480 = self.calcDB[i]['nTime'] - self.calcDB[i-tCount480]['nTime']
            tDB['bTime120'] = tDiffTime120 / float(tCount120)
            tDB['bTime480'] = tDiffTime480 / float(tCount480)
            
            tDB['BR'] = DEF_DB_STAT_CONSTANT_BRTIME / float(tTime)
            tDB['BR120'] = DEF_DB_STAT_CONSTANT_BRTIME / float(tDB['bTime120'])
            tDB['BR480'] = DEF_DB_STAT_CONSTANT_BRTIME / float(tDB['bTime480'])
            
            tDB['Chainworks'] = self.calcDB[i]['Chainworks'] - self.calcDB[i-1]['Chainworks']
            tDB['HPS'] = (self.calcDB[i]['Chainworks']-self.calcDB[i-1]['Chainworks']) / float(tTime)
            tDB['HPS120'] = (self.calcDB[i]['Chainworks']-self.calcDB[i-tCount120]['Chainworks']) / float(tDiffTime120)
            tDB['HPS480'] = (self.calcDB[i]['Chainworks']-self.calcDB[i-tCount480]['Chainworks']) / float(tDiffTime480)
            
            tDB['nTxs'] = self.calcDB[i]['nTxs']
            tDB['TPS'] = self.calcDB[i]['nTxs'] / float(tTime)
            tSumTsx = 0
            for j in range(i-tCount120+1,i+1):
                tSumTsx += self.calcDB[j]['nTxs']
            tDB['TPS120'] = tSumTsx / float(tDiffTime120)
            tSumTsx = 0
            for j in range(i-tCount480+1,i+1):
                tSumTsx += self.calcDB[j]['nTxs']
            tDB['TPS480'] = tSumTsx / float(tDiffTime480)
            
            #print ("%d,%d,%d,%d,%d,%d,%d,%d,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d") % (tIndex,tSumCount120,tSumCount480,tDiffTime120,tDiffTime480,tSumTxs120,tSumTxs480,tSumChainwork120,tSumChainwork480,tDB['bTime'],tDB['bTime120'],tDB['bTime480'],tDB['BR'],tDB['BR120'],tDB['BR480'],tDB['HPS'],tDB['HPS120'],tDB['HPS480'])
                    
            self.SaveDictToFiles(DEF_DB_FILE_MAINSTAT,tDB) 
            countStat += 1
        
        if(countStat<1):
            return 0
        
        return countStat
        
    # ///////////////////////////////////////////////////////////////////////
    
    def startGetPeriodeStat(self, countLoaded, indexPStatEnd):
        if (countLoaded<1) or (indexPStatEnd<0) :
            return -1
            
        if (countLoaded != self.calcDbCount):
            print "[ERROR] startGetPeriodeStat : loaded info mismatch: countLoaded=%d vs self.calcDbCount=%d" % (countLoaded, self.calcDbCount)
            return -1
        
        print "startGetPeriodeStat : from %d wiht %d" % (indexPStatEnd, countLoaded)
                
        eEndIndex = countLoaded-1
        tDB = DEF_DB_480B_DICT
        
        tChainwork = 0
        tBO = 0
        for i in range(0,countLoaded):
            tChainwork += self.calcDB[i]['Chainworks']
            tBO += self.calcDB[i]['BO']
            tDiff = self.calcDB[i]['DIFF']
        
        tIndex = self.calcDB[0][DEF_DB_FILE_HEADSTART]
        tDB[DEF_DB_FILE_HEADSTART] = self.calcDB[0][DEF_DB_FILE_HEADSTART]
        tDB['bIndexEnd'] = self.calcDB[eEndIndex][DEF_DB_FILE_HEADSTART]
        tDB['elapsedBI'] = countLoaded
        tDB['DiffIndex'] = (tIndex/DEF_DB_MIN_STAT_NUM) + 1
        tDB['StartTime'] = self.calcDB[0]['nTime'] - self.calcDB[0]['bTime']
        tDB['EndTime'] = self.calcDB[eEndIndex]['nTime']
        tDB['StartTimeLocal'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(tDB['StartTime']))
        tDB['EndTimeLocal'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(tDB['EndTime']))
        
        timePeriode = tDB['EndTime'] - tDB['StartTime']
        
        tDB['elapsedTime'] = timePeriode
        tDB['bTime480'] = timePeriode/float(countLoaded)
        tDB['BR480'] = DEF_DB_STAT_CONSTANT_BRTIME/float(tDB['bTime480'])
        tDB['Difficulty'] = tDiff
        tDB['BO'] = tBO
        tDB['HPS480'] = tChainwork/float(timePeriode)
        
        self.SaveDictToFiles(DEF_DB_FILE_STAT480B,tDB) 
        
        return countLoaded
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckAndUpdateMainStatDB(self, tip_height):
        cont = True
        bStatus = True
        
        indexRawStart = self.raw_start_index
        indexRawEnd = self.raw_db_height
        print "[CheckAndUpdateMainStatDB] indexRawStart=%d, indexRawEnd=%d" % (indexRawStart, indexRawEnd)        
                
        # 0. check update or not
        indexMainStatEnd = self.CheckDBIndex(False, DEF_DB_FILE_MAINSTAT)
        if (indexMainStatEnd<0):
            if (path.exists(DEF_DB_FILE_MAINSTAT)):
                removeFiles(DEF_DB_FILE_MAINSTAT)                
            indexMainStatEnd = indexRawStart
            headerString = ''
            for i in DEF_DB_MAINSTAT_DICT.keys():
                headerString += (i + ',')        
            AddToFiles(DEF_DB_FILE_MAINSTAT,headerString)
        elif(indexMainStatEnd == indexRawEnd):
            print "[CheckAndUpdateMainStatDB] Already sunchronized !!!"
            return True        
        
        if(indexMainStatEnd<indexRawStart):
            print "[ERROR] CheckAndUpdateMainStatDB : indexMainStatEnd=%d vs indexRawStart=%d" % (indexMainStatEnd, indexRawStart)
            return False        
        elif(indexMainStatEnd>indexRawEnd):
            print "[ERROR] CheckAndUpdateMainStatDB : indexMainStatEnd=%d vs indexRawEnd=%d" % (indexMainStatEnd, indexRawEnd)
            return False
                
        print "[CheckAndUpdateMainStatDB] indexRawStart=%d, indexRawEnd=%d, indexMainStatEnd=%d" % (indexRawStart, indexRawEnd, indexMainStatEnd)
        
        while(cont and bStatus):
            # check count old db
            oldcount = indexMainStatEnd - indexRawStart + 1
            if(oldcount<0):
                oldcount = 0
            elif(oldcount>DEF_DB_MIN_STAT_NUM):
                oldcount = DEF_DB_MIN_STAT_NUM
            
            newcount = indexRawEnd - indexMainStatEnd
            if(newcount>DEF_DB_MIN_STAT_NUM):
                newcount = DEF_DB_MIN_STAT_NUM
            elif(newcount<0):
                print "[ERROR] CheckAndUpdateMainStatDB : newcount = %d" % newcount
                cont = False
                bStatus = False
                break
            elif(newcount==0):
                cont = False
                break
            
            print "oldcount = %d, newcount=%d" % (oldcount, newcount)
            # load raw db with oldcount + newcount
            countLoaded = self.LoadDB(DEF_DB_FILE_RAW, DEF_DB_RAW_DICT, indexMainStatEnd-oldcount+1, oldcount+newcount)
            print "CheckAndUpdateMainStatDB : countLoaded= %d " % countLoaded
            if(countLoaded<0):
                cont = False
                bStatus = False
                break;
            elif(countLoaded==0):
                cont = False
                break;
            
            # get stat with raw db
            countUpdated = self.startGetMainStat(countLoaded, indexMainStatEnd, oldcount)
            print "CheckAndUpdateMainStatDB : countUpdated= %d " % countUpdated
            if(countUpdated<=0):
                cont = False
                bStatus = False
                break;
            
            indexMainStatEnd += countUpdated
            print "CheckAndUpdateMainStatDB : %d db was updated. latest=%d" % (countUpdated, indexMainStatEnd)
            
            if(indexMainStatEnd == tip_height):
                cont = False
                break
        
        return bStatus
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckAndUpdateSampleStatDB(self, tip_height, fName='', periode=0):
        cont = True
        bStatus = True
        
        indexRawStart = tip_height - self.raw_db_count + 1
        indexRawEnd = tip_height
        print "indexRawStart=%d, indexRawEnd=%d" % (indexRawStart, indexRawEnd)        
                
        # 0. check latest or remove
        indexSampleStatEnd = self.CheckDBIndex(False, fName)
        if(indexSampleStatEnd == tip_height):
            print "[CheckAndUpdateSampleStatDB] Already sunchronized !!!"
            return True
        else:
            if (path.exists(fName)):
                removeFiles(fName)
            
            headerString = ''
            for i in DEF_DB_SAMPLE_DICT.keys():
                headerString += (i + ',')        
            AddToFiles(fName,headerString)
        
        # 1. check expected start point
        expectedStartI = tip_height + 1
        expectedStartI -= periode*DEF_DB_MIN_STAT_NUM
        if(expectedStartI<indexRawStart):
            expectedStartI = indexRawStart

        # 2. copy from request index to end
        #bStatus = self.LoadMainStatDBAndCopy(DEF_DB_FILE_MAINSTAT, expectedStartI, fName)
        bStatus = self.LoadDB(DEF_DB_FILE_MAINSTAT, DEF_DB_MAINSTAT_DICT, expectedStartI, 0, True, fName)
        return bStatus  
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckAndUpdatePeriodeStatDB(self, tip_height):
        cont = True
        bStatus = True
        
        indexRawStart = tip_height - self.raw_db_count + 1
        indexRawEnd = tip_height
        
        expectedEnd = tip_height / DEF_DB_MIN_STAT_NUM
        expectedEnd *= DEF_DB_MIN_STAT_NUM
        expectedStart = indexRawStart / DEF_DB_MIN_STAT_NUM
        expectedStart += 1
        expectedStart *= DEF_DB_MIN_STAT_NUM
                
        # 0. check update or not. check update lator
        if 1:
            if (path.exists(DEF_DB_FILE_STAT480B)):
                removeFiles(DEF_DB_FILE_STAT480B)
            indexPStatEnd = expectedStart
            headerString = ''
            for i in DEF_DB_480B_DICT.keys():
                headerString += (i + ',')        
            AddToFiles(DEF_DB_FILE_STAT480B,headerString)
        else:
            indexPStatEnd = self.CheckDBIndex(False, DEF_DB_FILE_STAT480B)
            if (indexPStatEnd<0):
                indexPStatEnd = expectedStart
                headerString = ''
                for i in DEF_DB_480B_DICT.keys():
                    headerString += (i + ',')        
                AddToFiles(DEF_DB_FILE_STAT480B,headerString)
            elif(indexPStatEnd == expectedEnd):
                print "[CheckAndUpdatePeriodeStatDB] Already sunchronized !!!"
                # must be removed
                return True        
        
        if(indexPStatEnd>expectedStart):
            expectedStart = indexPStatEnd
        
        print "CheckAndUpdatePeriodeStatDB : check range : %d ~ %d" % (indexPStatEnd, indexRawEnd)
        
        while(cont and bStatus):
            newcount = indexRawEnd - indexPStatEnd
            if(newcount>DEF_DB_MIN_STAT_NUM):
                newcount = DEF_DB_MIN_STAT_NUM
            elif(newcount<0):
                print "[ERROR] CheckAndUpdatePeriodeStatDB : newcount = %d" % newcount
                cont = False
                bStatus = False
                break
            elif(newcount==0):
                cont = False
                break
            
            #print "newcount=%d" % (newcount)
            # load raw db with newcount
            countLoaded = self.LoadDB(DEF_DB_FILE_MAINSTAT, DEF_DB_MAINSTAT_DICT, indexPStatEnd, newcount)
            print "CheckAndUpdatePeriodeStatDB : countLoaded= %d " % countLoaded
            if(countLoaded<0):
                cont = False
                bStatus = False
                break;
            elif(countLoaded==0):
                cont = False
                break;
            
            # get stat with mainstat db
            countUpdated = self.startGetPeriodeStat(countLoaded, indexPStatEnd)
            print "CheckAndUpdatePeriodeStatDB : countUpdated= %d " % countUpdated
            if(countUpdated<=0):
                cont = False
                bStatus = False
                break;
            
            indexPStatEnd += countUpdated
            print "CheckAndUpdatePeriodeStatDB : %d db was updated. latest=%d" % (countUpdated, indexPStatEnd)
            
            if(indexPStatEnd == tip_height):
                cont = False
                break
            
        return bStatus
        
    # ///////////////////////////////////////////////////////////////////////
    
    def MakeItemStat(self, objDB=None, tNewDict=None, key='', fname=''):
        if (len(objDB)<1) or (len(tNewDict)<1) or (len(key)<1) or (len(fname)<1):
            return
        
        if (path.exists(fname)):
            removeFiles(fname)
        
        headerString = ''
        for i in tNewDict.keys():
            headerString += (i + ',')        
        AddToFiles(fname,headerString)
        
        bStatus = True
        tList = []
        itemCount = len(objDB)
        
        tMinerStatkeyList = MinerStatkeyList
        tMinerStatkeyList.append('Total')
        tMinerStatkeyListSecond = MinerStatkeyListSecond
        tMinerStatkeyListSecond.append('TotalP')
        
        statKeyCount = len(tMinerStatkeyList)
        statKeyCountSecond = len(tMinerStatkeyListSecond)
        
        for i in range(0, itemCount):
            tValue = objDB[i][key]
            if(len(tValue)<1) or (tValue=='None'):
                continue
            tCount = tList.count(tValue)
            if(tCount<1):
                tList.append(tValue)
        
        itemListCount = len(tList)
        
        if(itemListCount<1):
            return
        
        #check sum
        tTotalValueList = []
        for i in range(0, statKeyCount):
            tCount = 0
            for j in range(0, itemCount):
                tCount += objDB[j][tMinerStatkeyList[i]]
            tTotalValueList.append(tCount)
        
        # make new db
        tStatList = []
        for i in range(0, itemListCount):
            tDB = tNewDict
            tGrp = tList[i]
            tDB[key] = tGrp
            for j in range(0, statKeyCount):
                tCount = 0
                for k in range(0, itemCount):
                    if(objDB[k][key]==tGrp):
                        tCount += objDB[k][tMinerStatkeyList[j]]
                tDB[tMinerStatkeyList[j]] = tCount
            tStatList.append(tDB.copy()) 
        
        # update new db
        for i in range(0, itemListCount):
            for j in range(0, statKeyCount):
                if(tTotalValueList[j]>0):
                    tStatList[i][tMinerStatkeyListSecond[j]] = tStatList[i][tMinerStatkeyList[j]] / float(tTotalValueList[j])
                else:
                    tStatList[i][tMinerStatkeyListSecond[j]] = 0
        
        # sort
        tStatList.sort(key=operator.itemgetter('Total'), reverse=True)
        
        # make file
        for i in range(0, itemListCount):
            tDict = tStatList[i].copy()
            self.SaveDictToFiles(fname,tDict)
        
        print "[MakeItemStat] %s was made" % fname
        
        return  
    
    # ///////////////////////////////////////////////////////////////////////

    def CheckAndUpdateMinerStatDB(self, tip_height):
        cont = True
        bStatus = True
        
        # 0. check update or not. check update lator
        if (path.exists(DEF_DB_FILE_STAT_MINERLIST)):
            removeFiles(DEF_DB_FILE_STAT_MINERLIST)
        if (path.exists(DEF_DB_FILE_STAT_MINERSTAT)):
            removeFiles(DEF_DB_FILE_STAT_MINERSTAT)
        
        headerString = ''
        for i in DEF_DB_MINERLIST_DICT.keys():
            headerString += (i + ',')        
        AddToFiles(DEF_DB_FILE_STAT_MINERLIST,headerString)
        
        headerString = ''
        for i in DEF_DB_MINERSTAT_DICT.keys():
            headerString += (i + ',')        
        AddToFiles(DEF_DB_FILE_STAT_MINERSTAT,headerString)
        
        indexRawStart = tip_height - self.raw_db_count + 1
        
        lastPD = tip_height / DEF_DB_MIN_STAT_NUM                  # 176.xxx
        remain = tip_height % DEF_DB_MIN_STAT_NUM + 1
        startPD = lastPD - DEF_DB_MINER_STAT_CHECK_PERIODE + 1     # 157
        initialPD = indexRawStart / DEF_DB_MIN_STAT_NUM + 1
        expectedStartIndex = startPD * DEF_DB_MIN_STAT_NUM
        
        if(startPD<initialPD):
            startPD = initialPD
            expectedStartIndex = startPD * DEF_DB_MIN_STAT_NUM
        
        loopPD = lastPD - startPD
        if(loopPD<1):
            print "[ERROR] CheckAndUpdateMinerStatDB : check db count : startPD=%d vs lastPD=%d " % (startPD, lastPD)
            return False
        
        # 1. make miner list
        requiredCount = tip_height - expectedStartIndex + 1
        print "expectedStartIndex=%d, expectedStartIndex=%d" %(expectedStartIndex,requiredCount)
        countLoaded = self.LoadDBwithDict(DEF_DB_FILE_MAINSTAT, DEF_DB_MAINSTAT_DICT, DEF_DB_MINERLIST_DICT, expectedStartIndex, requiredCount)
        if(countLoaded!=requiredCount):
            print "[ERROR] CheckAndUpdateMinerStatDB : check db count : %d vs %d " % (countLoaded, requiredCount)
            return False
        
        minerList = []
        for i in range(0, self.calcDbCount):
            tMiner = ''
            tMiner = self.calcDB[i]['MinerAD']
            tDup = minerList.count(tMiner)
            if (tDup<1):
                minerList.append(tMiner)
        
        minerCount = len(minerList)
        
        minerStatList = []
        for i in range(0, minerCount):
            tDict = None
            tDict = DEF_DB_MINERSTAT_DICT
            tDict['MinerAD'] = minerList[i]
            minerStatList.append(tDict.copy())
        
        stepCount = remain
        if(remain<1):
            stepCount = DEF_DB_MIN_STAT_NUM
        
        endI = self.calcDbCount
        
        for i in range(0, endI):
            tDict = None
            tDict = self.calcDB[i].copy()
            self.SaveDictToFiles(DEF_DB_FILE_STAT_MINERLIST,tDict)
        
        for i in range(0, loopPD+1):
        #for i in range(0, 1):
            startI = endI - stepCount
            #print "%d ~ %d" % (startI, endI)
            if(startI<0):
                print "[ERROR] CheckAndUpdateMinerStatDB : check logic again : startI=%d, expectedStartIndex=%d" % (startI, expectedStartIndex)
                bStatus = False
                break
            
            tListCounted = []
            for j in range(startI, endI):
                tMiner = ''
                tMiner = self.calcDB[j]['MinerAD']
                tListCounted.append(tMiner)
                
            tOverCount = 0
            for j in range(0, minerCount):
                tCount = tListCounted.count(minerList[j])
                tOverCount += tCount
                minerStatList[j][MinerStatkeyList[i]] = tCount
                if(stepCount>0):
                    #minerStatList[j][MinerStatkeyListSecond[i]] = (tCount*100) / float(stepCount)
                    minerStatList[j][MinerStatkeyListSecond[i]] = tCount / float(stepCount)
                else:
                    minerStatList[j][MinerStatkeyListSecond[i]] = 0.
                #print "[%s] mined %d with %.2f%% " % (minerList[j], minerStatList[j][MinerStatkeyList[i]], minerStatList[j][MinerStatkeyListSecond[i]])
            
            if(tOverCount!=stepCount):
                print "[ERROR] CheckAndUpdateMinerStatDB : check logic again : tOverCount=%d, stepCount=%d" % (tOverCount, stepCount)
                bStatus = False
                break
            
            endI -= stepCount
            stepCount = DEF_DB_MIN_STAT_NUM     
        
        tTotCount = 0
        for i in range(0, minerCount):
            tSum = 0
            for j in range(0, len(MinerStatkeyList)):
                tSum += minerStatList[i][MinerStatkeyList[j]]
            tTotCount += tSum
            minerStatList[i]['Total'] = tSum
        
        for i in range(0, minerCount):
            if(tTotCount>0):
                minerStatList[i]['TotalP'] = minerStatList[i]['Total'] / float(tTotCount)
            else:
                minerStatList[i]['TotalP'] = 0.
        
        minerStatList.sort(key=operator.itemgetter('Total'), reverse=True)
        
        # update with miner info based on ref
        for i in range(0, minerCount):
            tDict = None
            tDict = DEF_DB_REF_GRP_AD_DICT
            tValue = minerStatList[i]['MinerAD']
            tDict = self.CheckGroupAD(tValue)
            tGrpAD = tDict['GRP_AD']            
            tfeedto = tDict['FEEDTO']
            minerStatList[i]['GRP_AD'] = tGrpAD
            
            tEtc = tDict['ETC']
            minerStatList[i]['ETC'] = tEtc
            
            if (len(tfeedto)<1) or (tfeedto=='None'):
                minerStatList[i]['GRP_FGI'] = 'None'
                minerStatList[i]['GRP_ACI'] = 'None'
            else:
                tDict = None
                tDict = DEF_DB_REF_GRP_AD_DICT
                tValue = tfeedto
                tDict = self.CheckFI(tValue)
                tFI = tDict['FI']
                if (len(tFI)<1) or (tFI=='None'):
                    minerStatList[i]['GRP_FGI'] = 'None'
                    minerStatList[i]['GRP_ACI'] = 'None'
                else:
                    tDict = None
                    tDict = DEF_DB_REF_FI_TO_FGI_DICT
                    tValue = tFI
                    tDict = self.CheckFGI(tValue)
                    tFgi = tDict['FGI']
                    minerStatList[i]['GRP_FGI'] = tFgi
                    
                    tDict = None
                    tDict = DEF_DB_REF_FI_TO_GRPACI_DICT
                    tDict = self.CheckGrpAci(tValue)
                    tAci = tDict['GRP_ACI']
                    minerStatList[i]['GRP_ACI'] = tAci
        
        # update with miner info based on grp
        for i in range(0, minerCount):
            tGrpAD = minerStatList[i]['GRP_AD']
            if (len(tGrpAD)<1) or (tGrpAD=='None'):
                continue
            tValue = minerStatList[i]['GRP_FGI']
            if (len(tValue)<1) or (tValue=='None'):
                minerStatList[i]['GRP_FGI'] = tGrpAD
            
            tValue = minerStatList[i]['GRP_ACI']
            if (len(tValue)<1) or (tValue=='None'):
                minerStatList[i]['GRP_ACI'] = tGrpAD
        
        # make main stat
        for i in range(0, minerCount):
            tDict = None
            tDict = minerStatList[i].copy()
            self.SaveDictToFiles(DEF_DB_FILE_STAT_MINERSTAT,tDict)     
        
        # make grp stat
        self.MakeItemStat(minerStatList, DEF_DB_MINERSTAT_SUB_GRP_DICT,'GRP_AD',DEF_DB_FILE_STAT_MINERSTAT_SUB_GRP)
        self.MakeItemStat(minerStatList, DEF_DB_MINERSTAT_SUB_FGI_DICT,'GRP_FGI',DEF_DB_FILE_STAT_MINERSTAT_SUB_FGI)
        self.MakeItemStat(minerStatList, DEF_DB_MINERSTAT_SUB_ACI_DICT,'GRP_ACI',DEF_DB_FILE_STAT_MINERSTAT_SUB_ACI)
        
        return bStatus
            
    # ///////////////////////////////////////////////////////////////////////
    
        
    # ////////////////////////////////////////////////////////////////////////
    
    def doMainProcedure(self, bOffline=False):
        # 1. check rawdb and update it
        bStatus = self.SyncChainWithRawDB(bOffline)
        if not bStatus:
            return False
            
        # 2. check statTotaldb and update it
        bStatus = self.CheckAndUpdateMainStatDB(self.tip_height)
        if not bStatus:
            return False
        
        # 3. get sample statistics
        bStatus = self.CheckAndUpdateSampleStatDB(self.tip_height, DEF_DB_FILE_STAT_MAXP, DEF_DB_STAT_SAMPLE_MAX_PERIODE)
        if not bStatus:
            return False
        
        bStatus = self.CheckAndUpdateSampleStatDB(self.tip_height, DEF_DB_FILE_STAT_MINP, DEF_DB_STAT_SAMPLE_MIN_PERIODE)
        if not bStatus:
            return False
        
        bStatus = self.CheckAndUpdatePeriodeStatDB(self.tip_height)
        if not bStatus:
            return False
        
        # 4. get miner statistics
        bStatus = self.CheckAndUpdateMinerStatDB(self.tip_height)
        if not bStatus:
            return False
        
        
        # get latest 4800 statistics
    # ////////////////////////////////////////////////////////////////////////






def main():
    ticks = time.time()
    mydb = MyChainDatabase()
    #mydb.doMainProcedure(True)
    mydb.doMainProcedure()
    
    ticks2 = time.time()
    print "[STAT] %d seconds elapsed !! " % (ticks2-ticks)
        
if __name__ == "__main__":
    main()