from FailSafeLearning.FailSafeSUL import FailSafeSUL
import constant
import colorama
import importlib
import random
from FailSafeLearning.Errors import ConnectionError
from FailSafeLearning.FailSafeSUL import FailSafeSUL

from BLEAdapter.NRF52_Driver import NRF52
from scapy.fields import RawVal
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.fields import RawVal
from time import sleep
from scapy.compat import raw
from colorama import Fore
from Crypto.Cipher import AES

try:
    importlib.import_module('BLESMPServer')
    import BLESMPServer
    ble_server = True
except:
    print(Fore.RED + "Please install the BLESMPServer if you want to test the pairing procedure.")
    ble_server = False

class BLESUL(FailSafeSUL):
    """
    Interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device.
    """
    EMPTY = 'Empty'

    def __init__(self, serial_port, advertiser_address):
        super().__init__()
        self.driver = NRF52(serial_port, debug=False, logs_pcap=constant.LOG_PCAP)
        self.slave_addr_type = 0

        rand_hex_str = hex(random.getrandbits(48))[2:]
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2])) 
        self.access_address = int(hex(random.getrandbits(32)),0)
        self.advertiser_address = advertiser_address

        self.connection_error_counter = 0

        self.encrypted = False
        self.conn_tx_packet_counter = 0
        self.conn_rx_packet_counter = 0
        self.conn_iv = b'\x00' * 8
        self.conn_skd = b'\x00' * 16
        self.conn_ltk = b'\x00' * 16
        self.conn_session_key = b'\x00' * 16
        self.confirm = b'\x00' * 16
        self.random = b'\x00' * 16
        self.conn_ltk_enc_inf = b'\x00' * 16
        self.rand = b'\x00' * 8
        self.ediv = 0
        self.irk = b'\x00' * 16
        self.csrk = b'\x00' * 16
        self.key_x = b'\x00' * 32
        self.key_y = b'\x00' * 32
        self.atype = 0
        self.dhkey_check = b'\x00' * 16
        
        colorama.init(autoreset=True)
    
    def bt_crypto_e(self, key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)
    
    def scan_request(self):
        """performs a scan request with less respons attempts"""
        # 'faster' learning parameter setup
        return self.scan_req(min_attempts=constant.MIN_ATTEMPTS, max_attempts=constant.MAX_ATTEMPTS)

    def scan_request_pkt(self):
        return BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=self.master_address,
        AdvA=self.advertiser_address)

    def scan_req(self, min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS):
        """
        sends a scan request and tries to receive a response

        Args:
            min_attempts: minimum number of attempts to receive a response
            max_attempts: maximum number of attempts to receive a response

        Returns: 
            'Adv' if a valid scan response was received or an error, if no 
            response was received
        """
        self.encrypted = False
        scan_req = self.scan_request_pkt()
        self.driver.send(scan_req)
        pkt = None
        received_data = set()
        attempt = 0
        while len(received_data) == 0 and attempt < min_attempts or (len(received_data) == 0 and attempt < max_attempts):
            # Receive packet from the NRF52 Dongle
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and hasattr(pkt, 'AdvA') and hasattr(pkt.AdvA, 'upper') and self.advertiser_address.upper() == pkt.AdvA.upper():
                    self.slave_addr_type = pkt.TxAdd
                    summary = pkt.summary()
                    print(Fore.MAGENTA + "RX <--- " + summary)
                    received_data.update(summary.split(" / "))
            attempt = attempt + 1
            sleep(0.01)
        
        if len(received_data) > 0:
            return "Adv"
        else:
            return constant.ERROR
    
    def contains_more_data(self, received_data): 
        """
        method to check if received data contains any package and more  
        packages than BTLE_DATA

        Args:
            received_data: received data from the peripheral

        Returns: 
            True if a package that contains more than BTLE_DATA has been received, otherwise False
        """
        base_data = {"BTLE", "BTLE_DATA"}
        return len(received_data) > 0 and (base_data != received_data)

    def send_hci(self, pkt):
        raw_pkt = raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / pkt[SM_Hdr])
        smp_answer = BLESMPServer.send_hci(raw_pkt)
        if smp_answer is not None and isinstance(smp_answer, list):
            for res in smp_answer:
                res = HCI_Hdr(res)
                if SM_Confirm in res:
                    self.confirm = res.confirm
                elif SM_Random in res:
                    self.random = res.random
                elif HCI_Cmd_LE_Start_Encryption_Request in res:
                    self.conn_ltk = res.ltk
                elif SM_Encryption_Information in res:
                    self.conn_ltk_enc_inf = res.ltk
                elif SM_Master_Identification in res:
                    self.ediv = res.ediv
                    self.rand = res.rand
                elif SM_Identity_Information in res:
                    self.irk = res.irk
                elif SM_Identity_Address_Information in res:
                    self.atype = res.atype
                elif SM_Signing_Information in res:
                    self.csrk = res.csrk
                elif SM_Public_Key in res:
                    self.key_x = res.key_x
                    self.key_y = res.key_y
                elif SM_DHKey_Check in res:
                    self.dhkey_check = res.dhkey_check

    def send_pkt(self, pkt):
        if self.encrypted:
            self.send_encrypted(pkt)
        else: 
            self.driver.send(pkt)
    
    def public_key_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key(key_x=self.key_x, key_y=self.key_y)

    def public_key(self):
        pkt = self.public_key_pkt()
        self.send_pkt(pkt)
        return self.receive_data()

    def dhkey_check_ind_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_DHKey_Check(dhkey_check=self.dhkey_check)

    def dhkey_check_ind(self):
        pkt = self.dhkey_check_ind_pkt()
        self.send_pkt(pkt)
        return self.receive_data()

    def encryption_information_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Encryption_Information(ltk=self.conn_ltk_enc_inf)

    def encryption_information(self):
        pkt = self.encryption_information_pkt()
        self.send_pkt(pkt)
        return self.receive_data()
    
    def master_identification_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Master_Identification(ediv=self.ediv, rand=self.rand)
    
    def master_identification(self):
        pkt = self.master_identification_pkt()
        self.send_pkt(pkt)
        return self.receive_data()

    def identity_information_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Identity_Information(irk=self.irk)
    
    def identity_information(self):
        pkt = self.identity_information_pkt()
        self.send_pkt(pkt)
        return self.receive_data()

    def identity_address_information_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Identity_Address_Information(atype=self.atype)

    def identity_address_information(self):
        pkt = self.identity_address_information_pkt()
        self.send_pkt(pkt)
        return self.receive_data()
    
    def signing_information_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Signing_Information(csrk=self.csrk)

    def signing_information(self):
        pkt = self.signing_information_pkt()
        self.send_pkt(pkt)
        return self.receive_data()
    
    def process_received_pkt(self, pkt):
        received_data = set()
        if SM_Hdr in pkt and ble_server:
            self.send_hci(pkt)
        elif LL_ENC_RSP in pkt:
            self.conn_skd = b'\x00' * 8 + struct.pack("<Q",pkt[LL_ENC_RSP].skds)  # SKD = SKDm || SKDs
            iv = struct.pack("<Q",pkt[LL_ENC_RSP].ivs) 
            self.conn_iv = b'\x00' * 4 + bytearray(iv)[:-4] # IV = IVm || IVs
            self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
        elif BTLE_CTRL in pkt:
            ctrl_content = bytearray([bytearray(raw(pkt))[6]])
            start_enc_pkt = BTLE() / BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_REQ()
            if ctrl_content == bytearray([start_enc_pkt.opcode]):
                self.encrypted = True
                received_data.add("LL_START_ENC_REQ")
        received_data.update(pkt.summary().split(" / "))
        return received_data

    
    def receive_data(self, min_attempts=constant.MIN_ATTEMPTS, max_attempts=constant.MAX_ATTEMPTS):
        """
        receives data from the peripheral. The attempt to receive data 
        is repeated at least min_attempts, but at maximum max_attempts

        Args:
            min_attempts: minimum number of attempts to receive a response
            max_attempts: maximum number of attempts to receive a response

        Returns: 
            set of received packages in alphabetical order, if no packages is 
            received empty is returned
        """
        pkt = None
        attempts = 0
        received_data = set()
        while attempts < min_attempts or (not self.contains_more_data(received_data) and attempts < max_attempts):
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None:
                    if self.encrypted:
                        raw_pkt = bytearray(raw(pkt))
                        aa = raw_pkt[:4]
                        header = bytearray([raw_pkt[4]]) 
                        length = raw_pkt[5]
                        if length >= 5:
                            length -= 4  
                            pkt_count = bytearray(struct.pack("<Q", self.conn_rx_packet_counter)[:5])  # convert only 5 bytes
                            pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
                            nonce = pkt_count + self.conn_iv
                            aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
                            #aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD
                            aes.update(bytes([header[0] & b'\xE3'[0]]))
                            dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc
                            self.conn_rx_packet_counter += 1
                            try:
                                mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
                                aes.verify(mic)
                                pkt = BTLE(aa + header + bytearray([length]) + dec_pkt + b'\x00\x00\x00')
                            except Exception as e:
                                pkt = BTLE(aa + header + bytearray([length]) + dec_pkt + b'\x00\x00\x00')
                            if BTLE_DATA in pkt:
                                received_data.update(self.process_received_pkt(pkt))
                                print(Fore.MAGENTA + "RX <--- [Encrypted]{" + pkt.summary() + "}")
                    else:     
                        if BTLE_DATA in pkt:
                            if SM_Pairing_Response in pkt:
                                print('Slave auth: ' + hex(pkt.authentication))
                            received_data.update(self.process_received_pkt(pkt))
                            print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                        
            attempts = attempts + 1
            sleep(0.01)
        return "|".join(sorted(received_data)) if len(received_data) > 0 else self.EMPTY

    def connection_request_pkt(self):
        self.encrypted = False
        return BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.advertiser_address,
            AA=self.access_address,  # Access address (any)
            crc_init=0x179a9c,  # CRC init (any)
            win_size=2,  # 2.5 of windows size (anchor connection window size)
            win_offset=1,  # 1.25ms windows offset (anchor connection point)
            interval=16,  # 20ms connection interval
            latency=0,  # Slave latency (any)
            timeout=50,  # Supervision timeout, 500ms (any)
            chM=0x1FFFFFFFFF,  # Any
            hop=5,  # Hop increment (any)
            SCA=0,  # Clock tolerance
        )

    def connection_request(self):
        """
        sends a connection request and tries to receive a response

        Returns: 
            received response or an error, if no response was received
        """
        conn_request = self.connection_request_pkt()
        self.driver.send(conn_request)
        received_data = self.receive_data(min_attempts=constant.CONNECT_MIN_ATTEMPTS, max_attempts=constant.CONNECT_MAX_ATTEMPTS)
        if received_data == self.EMPTY:
            return constant.ERROR
        else:
            return received_data

    def length_request_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_REQ(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
    
    def length_request(self):
        """
        sends a length request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_req = self.length_request_pkt()
        self.send_pkt(length_req)
        return self.receive_data()

    def length_response_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)

    def length_response(self):
        """
        sends a length response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_rsp = self.length_response_pkt()
        self.send_pkt(length_rsp)
        return self.receive_data()

    def feature_request_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_REQ(
                    feature_set='le_encryption+le_data_len_ext')
    
    def feature_request(self):
        """
        sends a feature request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_req = self.feature_request_pkt()
        self.send_pkt(feature_req)
        return self.receive_data()
    
    def feature_response_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_RSP(
                    feature_set='le_encryption+le_data_len_ext')

    def feature_response(self):
        """
        sends a feature response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_rsp = self.feature_response_pkt()
        self.send_pkt(feature_rsp)
        return self.receive_data()
    
    def group_type_request_pkt(self):
        return BTLE(access_addr=self.access_address) / \
                    BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Group_Type_Request(start=0x0001,end=0xffff, uuid=0x2800)

    def group_type_request(self):
        """
        sends mtu request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        group_type_req = self.group_type_request_pkt()
        self.send_pkt(group_type_req)
        return self.receive_data()

    def mtu_response_pkt(self):
        return BTLE(access_addr=self.access_address) / \
                    BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Response(mtu=247)
    
    def mtu_response(self):
        """
        sends mtu request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        mtu_rsp = self.mtu_response_pkt()
        self.send_pkt(mtu_rsp)
        return self.receive_data()
    
    def mtu_request_pkt(self):
        return BTLE(access_addr=self.access_address) / \
                    BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
    
    def mtu_request(self):
        """
        sends mtu request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        mtu_req = self.mtu_request_pkt()
        self.send_pkt(mtu_req)
        return self.receive_data()
    
    def version_request_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_VERSION_IND(version='5.0')
    
    def version_request(self):
        """
        sends version request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        version_req = self.version_request_pkt()
        self.send_pkt(version_req)
        return self.receive_data()
    
    def termination_indication_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_TERMINATE_IND()
    
    def termination_indication(self):
        # self.encrypted = False
        termination_ind = self.termination_indication_pkt()
        self.send_pkt(termination_ind)
        return self.receive_data(min_attempts=constant.TERMINATE_MIN_ATTEMPTS,max_attempts=constant.TERMINATE_MAX_ATTEMPTS)
    
    def pause_enc_request_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_PAUSE_ENC_REQ()
    
    def pause_enc_request(self):
        #self.encrypted = False
        pause_enc_req = self.pause_enc_request_pkt()
        self.send_pkt(pause_enc_req)
        return self.receive_data()

    
    def pairing_request_smp(self, pairing_auth_request):
        """
        sends pairing request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        pairing_iocap = 0x03 #NoInputNoOutput

        master_address_raw = bytes.fromhex(self.master_address.replace(":", ""))
        slave_address_raw = bytes.fromhex(self.advertiser_address.replace(":", ""))
        BLESMPServer.set_pin_code('\x00' * 4)
        BLESMPServer.configure_connection(master_address_raw, slave_address_raw, 0, pairing_iocap, pairing_auth_request)
        hci_res = BLESMPServer.pairing_request()
        hci_res = hci_res.encode()
        if hci_res:
            hci_res_pkt = HCI_Hdr(hci_res)
            if SM_Hdr in hci_res_pkt:
                pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                return pkt

        return None

    def pairing_request_pkt(self, authentication):
        pairing_req = None
        if not ble_server:
            pairing_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(iocap=0x03, oob=0, authentication=authentication, max_key_size=16, initiator_key_distribution=0x07, responder_key_distribution=0x07)
        else:
            pairing_req  = self.pairing_request_smp(authentication)
        return pairing_req


    def pairing_request(self, authentication = 0x01):
        pairing_req = self.pairing_request_pkt(authentication)
        self.send_pkt(pairing_req)
        return self.receive_data()

    def secure_pairing_request(self):
        """
        sends pairing request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        return self.pairing_request(0x08 | 0x01)

    def legacy_pairing_request(self):
        """
        sends pairing request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        return self.pairing_request(0x01)

    
    def sm_confirm_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm(confirm=self.confirm)

    def sm_confirm(self):
        sm_confirm_req = self.sm_confirm_pkt()
        self.send_pkt(sm_confirm_req)
        return self.receive_data()
    
    def sm_random_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Random(random=self.random)

    def sm_random(self):
        sm_random_req = self.sm_random_pkt()
        self.send_pkt(sm_random_req)
        return self.receive_data()

    def ll_enc_request_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_ENC_REQ(ediv=0,rand=RawVal(b'\x00' * 4),skdm=RawVal(self.conn_skd[:8]),ivm=RawVal(self.conn_iv))

    def ll_enc_request(self):
        # self.conn_iv = b'\x00' * 8  # set IVm (IV of master)
        # self.conn_skd = b'\x00' * 16  # set SKDm (session key diversifier part of master)
        self.send_pkt(self.ll_enc_request_pkt())
        return self.receive_data()

    def ll_start_enc_response_pkt(self):
        return BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_RSP()

    def ll_start_enc_response(self):
        pkt = self.ll_start_enc_response_pkt()
        self.send_pkt(pkt)
        return self.receive_data()

    def send_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        aa = raw_pkt[:4] # access address
        header = bytearray([raw_pkt[4]])
        length = bytearray([raw_pkt[5] + 4])  
        crc = b'\x00\x00\x00' 
        pkt_count = bytearray(struct.pack("<Q", self.conn_tx_packet_counter)[:5]) 
        pkt_count[4] |= 0x80 
        nonce = pkt_count + self.conn_iv
        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4) 
        aes.update(bytes([header[0] & b'\xE3'[0]]))   
        enc_pkt, mic = aes.encrypt_and_digest(bytes(raw_pkt[6:-3])) 
        self.conn_tx_packet_counter += 1 
        aa_raw = bytes(aa)
        pkt_send = bytearray(aa_raw) + bytearray(header) + bytearray(length) + bytearray(enc_pkt) + bytearray(mic) + bytearray(crc)
        self.driver.raw_send(pkt_send)
        print(Fore.CYAN + "TX ---> [Encrypted]{" + pkt.summary()+ '}')
    
    def reconnect(self):
        self.termination_indication()
        self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)

    def keep_alive_connection(self):
        """
        sends a connection request to avoid that peripheral enters a standby 
        state. The connection is reset afterwards by a scan request.
        In case of a connection error, the procedure is repeated.
        """
        error_counter = 0
        output = constant.ERROR
        while output == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            output_con = self.connection_request()
            output_scan = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
            if (output_con == constant.ERROR or output_scan == constant.ERROR):
                self.reconnect()
                output = constant.ERROR
            else:
                output = ''
            error_counter += 1
            self.connection_error_counter += 1
        
        if error_counter >= constant.CONNECTION_ERROR_ATTEMPTS and output == constant.ERROR:
            raise ConnectionError()

    
    def default(self):
        return "invalid input provided"
        
    def pre(self):
        """
        resets the peripheral including a keep alive message to avoid that 
        peripheral enters standby state
        """
        rand_hex_str = hex(random.getrandbits(48))[2:]
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2])) 
        self.access_address = int(hex(random.getrandbits(32)),0)

        self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
        self.keep_alive_connection()

        self.encrypted = False
        self.conn_tx_packet_counter = 0
        self.conn_rx_packet_counter = 0
        self.conn_iv = b'\x00' * 8
        self.conn_skd = b'\x00' * 16
        self.conn_session_key = b'\x00' * 16
        self.confirm = b'\x00' * 16
        self.random = b'\x00' * 16
        self.conn_ltk = b'\x00' * 16
        self.conn_ltk_enc_inf = b'\x00' * 16
        self.rand = b'\x00' * 8
        self.ediv = 0
        self.irk = b'\x00' * 16
        self.csrk = b'\x00' * 16
        self.key_x = b'\x00' * 32
        self.key_y = b'\x00' * 32
        self.atype = 0
        self.dhkey_check = b'\x00' * 16

    def post(self):
        """
        sends keep alive message to avoid that peripheral enters standby state 
        """
        self.termination_indication()
        
    def step(self, letter):
        """
        performs a step in the output query. Abstract inputs are mapped
        to concrete methods
        """
        requests = {
            "scan_req": {"method": self.scan_request, "params": {}},
            "connection_req": {"method": self.connection_request, "params": {}},
            "version_req": {"method": self.version_request, "params": {}},
            "length_req": {"method": self.length_request, "params": {}},
            "length_rsp": {"method": self.length_response, "params": {}},
            "mtu_req": {"method": self.mtu_request, "params": {}},
            "mtu_rsp": {"method": self.mtu_response, "params": {}},
            "feature_req": {"method": self.feature_request, "params": {}},
            "feature_rsp": {"method": self.feature_response, "params": {}},
            "legacy_pairing_req": {"method": self.legacy_pairing_request, "params": {}},
            "secure_pairing_req": {"method": self.secure_pairing_request, "params": {}},
            "pairing_req": {"method": self.pairing_request, "params": {}},
            "sm_confirm": {"method": self.sm_confirm, "params": {}},
            "sm_random": {"method": self.sm_random, "params": {}},
            "group_type_request": {"method": self.group_type_request, "params": {}},
            "ll_enc_request": {"method": self.ll_enc_request, "params": {}},
            "ll_start_enc_response": {"method": self.ll_start_enc_response, "params": {}},
            "encryption_information": {"method": self.encryption_information, "params": {}},
            "master_identification": {"method": self.master_identification, "params": {}},
            "identity_information": {"method": self.identity_information, "params": {}},
            "identity_address_information": {"method": self.identity_address_information, "params": {}},
            "termination_ind": {"method": self.termination_indication, "params": {}},
            "signing_information": {"method": self.signing_information, "params": {}}
        }
        request = requests.get(letter, {"method": self.default})
        output = request["method"](**request.get("params", {}))
        return output
    
    def query(self, word):
        """
        Performs an output query on the SUL.
        Before the query, pre() method is called and after the query post()
        method is called. Each letter in the word (input in the input sequence) 
        is executed using the step method. If the step method returns an error, 
        the query gets repeated.

        Args:

            word: output query (word consisting of inputs)

        Returns:

            list of observed outputs, where the i-th output corresponds to the output of the system after the i-th input

        """
        self.performed_steps_in_query = 0
        out = constant.ERROR
        error_counter = 0
        while out == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            self.pre()
            outputs = []
            num_steps = 0
            for letter in word:
                out = self.step(letter)
                num_steps += 1
                if out == constant.ERROR:
                    print(Fore.RED + "ERROR reported")
                    self.connection_error_counter += 1
                    self.post()
                    self.num_queries += 1
                    self.performed_steps_in_query += num_steps
                    self.num_steps += num_steps
                    break
                outputs.append(out)
            if out == constant.ERROR:
                error_counter += 1
                continue
            self.post()
            self.num_queries += 1
            self.performed_steps_in_query += len(word)
            self.num_steps += len(word)
            return outputs

        raise ConnectionError()
    
    def save_pcap(self, pcap_filename):
        self.driver.save_pcap(pcap_filename)
