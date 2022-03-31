from time import sleep
import constant
import time

from BLESUL import BLESUL
from colorama import Fore



class BLESULConnectingStart(BLESUL):
    """
    Interface for the interaction with a BLE peripheral. Commands to the peripheral are sent via a central device. This interface always establishes a connection before the execution of an input sequence.
    """

    MAX_PHYSICAL_RESET = 10

    waiting_time = 0
    
    def __init__(self, serial_port, advertiser_address):
        super().__init__(serial_port, advertiser_address)

        
    def pre(self):
        """
        resets the peripheral including a keep alive message to avoid that 
        peripheral enters standby state
        """
        scan_rsp = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
        conn_rsp = self.connection_request()
        physical_reset_attempts = 0
        while physical_reset_attempts < self.MAX_PHYSICAL_RESET:
            if scan_rsp == constant.ERROR or conn_rsp == constant.ERROR:
                self.termination_indication()
                scan_rsp = self.scan_req(min_attempts=constant.SCAN_MIN_ATTEMPTS, max_attempts=constant.SCAN_MAX_ATTEMPTS)
                conn_rsp = self.connection_request()
                physical_reset_attempts += 1
                if scan_rsp != constant.ERROR and conn_rsp != constant.ERROR:
                    break
                else:
                    if constant.PHYSICAL_RESET:
                        start_interrupt = time.time()
                        input(Fore.RED + "SUL might have crashed. Physical reset the device and press any key to continue...")
                        end_interrupt = time.time()
                        self.waiting_time += end_interrupt - start_interrupt
            else:
                break
                
        if physical_reset_attempts >= constant.SCAN_MAX_ATTEMPTS:
            raise SystemExit("SUL crashed!")


    def post(self):
        """
        connection is terminated after performing input sequence 
        """
        self.termination_indication()

    
    
