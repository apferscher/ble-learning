import constant
import colorama
from FailSafeLearning.ConnectionError import ConnectionError

from aalpy.base import SUL
from BLEAdapter.NRF52_Driver import NRF52
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from time import sleep
from colorama import Fore

class BLESUL(SUL):
    """
    Interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device.
    """
    EMPTY = 'Empty'

    def __init__(self, serial_port, advertiser_address):
        super().__init__()
        self.driver = NRF52(serial_port, debug=False, logs_pcap=constant.LOG_PCAP)

        self.slave_addr_type = 0
        self.master_address = '5d:36:ac:90:0b:22'
        self.access_address = 0x9a328370
        self.advertiser_address = advertiser_address
        self.connection_error_counter = 0
        colorama.init(autoreset=True)
    
    def scan_request(self):
        """performs a scan request with less respons attempts"""
        # 'faster' learning parameter setup
        return self.scan_req(min_attempts=5, max_attempts=20)

    def scan_req(self, min_attempts=20, max_attempts=100):
        """
        sends a scan request and tries to receive a response

        Args:
            min_attempts: minimum number of attempts to receive a response
            max_attempts: maximum number of attempts to receive a response

        Returns: 
            'Adv' if a valid scan response was received or an error, if no 
            response was received
        """
        scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
        ScanA=self.master_address,
        AdvA=self.advertiser_address)
        self.driver.send(scan_req)
        pkt = None
        received_data = set()
        attempt = 0
        while len(received_data) == 0 and attempt < min_attempts or (len(received_data) == 0 and attempt < max_attempts):
            # Receive packet from the NRF52 Dongle
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and hasattr(pkt, 'AdvA') and self.advertiser_address.upper() == pkt.AdvA.upper():
                    self.slave_addr_type = pkt.TxAdd
                    summary = pkt.summary()
                    print(Fore.MAGENTA + "RX <--- " + summary)
                    received_data.update(summary.split(" / "))
            attempt = attempt + 1
            sleep(0.01)
        return "Adv" if len(received_data) > 0 else constant.ERROR
    
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
    
    def receive_data(self, min_attempts=40, max_attempts=60):
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
                    if BTLE_DATA in pkt:
                        summary = pkt.summary()
                        print(Fore.MAGENTA + "RX <--- " + summary)
                        received_data.update(summary.split(" / "))
            attempts = attempts + 1
            sleep(0.01)
        return "/".join(sorted(received_data)) if len(received_data) > 0 else self.EMPTY


    def connection_request(self):
        """
        sends a connection request and tries to receive a response

        Returns: 
            received response or an error, if no response was received
        """
        conn_request = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
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
        self.driver.send(conn_request)
        received_data = self.receive_data()
        return constant.ERROR if received_data == self.EMPTY else received_data
    
    def length_request(self):
        """
        sends a length request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_REQ(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
        self.driver.send(length_req)
        return self.receive_data()

    def length_response(self):
        """
        sends a length response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        length_rsp = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
        self.driver.send(length_rsp)
        return self.receive_data()
    
    def feature_request(self):
        """
        sends a feature request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_REQ(
                    feature_set='le_encryption+le_data_len_ext')
        self.driver.send(feature_req)
        return self.receive_data()

    def feature_response(self):
        """
        sends a feature response and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        feature_resp = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_RSP(
                    feature_set='le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext')
        self.driver.send(feature_resp)
        return self.receive_data()
    
    def mtu_request(self):
        """
        sends mtu request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        mtu_req = BTLE(access_addr=self.access_address) / \
                    BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
        self.driver.send(mtu_req)
        return self.receive_data()
    
    def version_request(self):
        """
        sends version request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        version_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_VERSION_IND(version='5.0')
        self.driver.send(version_req)
        return self.receive_data()
    
    def pairing_request(self):
        """
        sends pairing request and listens for respones afterwards

        Returns: 
            received response or an empty indication 
        """
        pairing_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(iocap=0x04, oob=0, authentication= 0x08 | 0x40 | 0x01, max_key_size=16, initiator_key_distribution=0x07, responder_key_distribution=0x07)
        self.driver.send(pairing_req)
        return self.receive_data()
    
    def termination_indication(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_TERMINATE_IND()
        self.driver.send(pkt)
        return self.receive_data()

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
            output_scan = self.scan_req(min_attempts=5, max_attempts=100)
            output = constant.ERROR if (output_con == constant.ERROR or output_scan == constant.ERROR) else ''
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
        self.scan_req(min_attempts=5, max_attempts=100)
        self.keep_alive_connection()
        termination_output = self.termination_indication()
        if termination_output != self.EMPTY:
            print(Fore.YELLOW + "WARNING: Connection was not properly reset.")



    def post(self):
        """
        sends keep alive message to avoid that peripheral enters standby state 
        """
        self.keep_alive_connection()
        termination_output = self.termination_indication()
        if termination_output != self.EMPTY:
            print(Fore.YELLOW + "WARNING: Connection was not properly reset.")


    def step(self, letter):
        """
        performs a step in the output query. Abstract inputs are mapped
        to concrete methods
        """
        # mapper
        requests = {
            "scan_req": {"method": self.scan_request, "params": {}},
            "connection_req": {"method": self.connection_request, "params": {}},
            "version_req": {"method": self.version_request, "params": {}},
            "length_req": {"method": self.length_request, "params": {}},
            "length_rsp": {"method": self.length_response, "params": {}},
            "mtu_req": {"method": self.mtu_request, "params": {}},
            "feature_req": {"method": self.feature_request, "params": {}},
            "feature_rsp": {"method": self.feature_response, "params": {}},
            "pairing_req": {"method": self.pairing_request, "params": {}}
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
                    sleep(5)
                    self.num_queries += 1
                    self.num_steps += num_steps
                    break
                outputs.append(out)
            if out == constant.ERROR:
                error_counter += 1
                continue
            self.post()
            self.num_queries += 1
            self.num_steps += len(word)
            return outputs

        raise ConnectionError()
    
    def save_pcap(self, pcap_filename):
        self.driver.save_pcap(pcap_filename)