from xml.etree.ElementTree import VERSION
import constant
from colorama import Fore
import random
import time

from BLESUL import BLESUL
from FailSafeLearning.Errors import ConnectionError
from BLEAdapter.NRF52_Driver import NRF52
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *

class BLESULPairing(BLESUL):
    """
    Interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device.
    """

    physical_reset = False
    
    def __init__(self, serial_port, advertiser_address, physical_reset = False):
        self.physical_reset = physical_reset
        self.connection_physical_reset = 0
        self.connection_physical_reset_time = 0
        self.feature_request = False
        super().__init__(serial_port, advertiser_address)
        

    def check_rsp(self, response, terminate = True):
        if response == self.EMPTY or response == constant.ERROR:
            return False
        else:
            return True
    
    def react_to_request(self, response):

        while response is not None:
            if LL_SLAVE_FEATURE_REQ().summary() in response:
                response = response.replace(LL_SLAVE_FEATURE_REQ().summary(),"")
                response += self.feature_response()
            elif LL_LENGTH_REQ().summary() in response:
                response = response.replace(LL_LENGTH_REQ().summary(),"")
                response += self.length_response()
            elif ATT_Exchange_MTU_Request().summary() in response:
                response = response.replace(ATT_Exchange_MTU_Request().summary(),"")
                response += self.mtu_response()
            elif LL_VERSION_IND().summary() in response:
                response = response.replace(LL_VERSION_IND().summary(),"")
                response += self.version_request()
            else:
                response = None
        
    def pre_pairing_procedure(self):
        """
        establish connection and negotiate initial parameters. SUL should be ready for pairing afterwards.
        """
        error_counter = 0
        while error_counter <= constant.CONNECTION_ERROR_ATTEMPTS:
            if error_counter >= constant.CONNECTION_ERROR_ATTEMPTS:
                if self.physical_reset:
                    start_time = time.time()
                    input(Fore.RED + "SUL might have crashed. Physical reset the device and press any key to continue...")
                    self.connection_physical_reset_time = time.time() - start_time
                    self.connection_physical_reset += 1
                    error_counter = 0
                    continue
                else:
                    raise ConnectionError()

            response = self.scan_req()
            if not self.check_rsp(response):
                error_counter += 1 
                continue
            response = self.connection_request()
            if not self.check_rsp(response, terminate=False):
                    self.termination_indication()
                    error_counter += 1 
                    continue
            self.react_to_request(response)
            return

        
    def pre(self):
        """
        reset connection & pairing parameters
        establish connection to SUL & prepare SUL for pairing
        """
        self.encrypted = False
        self.conn_tx_packet_counter = 0
        self.conn_rx_packet_counter = 0

        # generate random master address
        rand_hex_str = hex(random.getrandbits(48))[2:]
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2]))
        # generate random access address
        self.access_address = int(hex(random.getrandbits(32)),0) 

        # reset pairing parameters
        self.conn_iv = b'\x00' * 8
        self.conn_skd = b'\x00' * 16
        self.conn_session_key = b'\x00' * 16
        self.conn_ltk = b'\x00' * 16
        self.sm_hdr_pkt = None
        self.confirm = b'\x00' * 16
        self.random = b'\x00' * 16
        self.conn_ltk_enc_inf = b'\x00' * 16
        self.rand = b'\x00' * 8
        self.ediv = 0
        self.irk = b'\x00' * 16
        self.csrk = b'\x00' * 16
        self.key_x = b'\x00' * 32
        self.key_y = b'\x00' * 32
        self.dhkey_check = b'\x00' * 16
        self.atype = 0

        #establish connection and perform prior requests to enable pairing 
        self.pre_pairing_procedure()
        

    def post(self):
        """
        sends keep alive message to avoid that peripheral enters standby state 
        """
        if self.encrypted:
            self.pause_enc_request()
        self.encrypted = False
        self.termination_indication()    
        
