import serial

from colorama import Fore

from scapy.utils import raw

###
# The code used in this file is copied from the SweynTooth project:
# https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks
#
# Following file/class has been copied:
# -- drivers/NRF52_dongle.py (class NRF52DONGLE)
#
# Minor adaptions to the existing code have been made:
# -- Adaptions for python3 usage  
# -- Removal of functionalities that are no longer required
#
# Date of copy: 04/21/2021
#
###

NRF52_CMD_DATA = b'\xA7'
NRF52_CMD_DATA_TX = b'\xBB'
NRF52_CMD_CHECKSUM_ERROR = b'\xA8'
NRF52_CMD_CONFIG_AUTO_EMPTY_PDU = b'\xA9'
NRF52_CMD_CONFIG_ACK = b'\xAA'
NRF52_CMD_CONFIG_LOG_TX = b'\xCC'
NRF52_CMD_CONFIG_NESNSN = b'\xAD'
NRF52_CMD_CONFIG_NESN = b'\xAE'
NRF52_CMD_CONFIG_SN = b'\xAF'
NRF52_CMD_BOOTLOADER_SEQ1 = b'\xA6'
NRF52_CMD_BOOTLOADER_SEQ2 = b'\xC7'
NRF52_CMD_LOG = b'\x7F'


class NRF52:
    """ 
        Driver for nRF2850 dongle or development-kit (dk)
    """

    n_debug = False
    n_log = False
    event_counter = 0
    packets_buffer = []
    sent_pkt = None


    def __init__(self, port_name=None, baudrate=115200, debug=False, logs=True):

        if port_name is None:
            print(Fore.RED + 'No port name of nRF52840 provided!')
            
        self.serial = serial.Serial(port_name, baudrate, timeout=1)
        self.n_log = logs
        self.n_debug = debug

        self.set_log_tx(0)

        if self.n_debug:
            print('NRF52 Dongle: Instance started')

    
    def raw_send(self, pkt):
        raw_pkt = bytearray(pkt[:-3])  # Cut the 3 bytes CRC
        crc = bytearray([sum(raw_pkt) & 0xFF])  # Calculate CRC of raw packet data
        pkt_len = len(raw_pkt)  # Get raw packet data length
        l = bytearray([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF])  # Pack length in 2 bytes (little infian)
        data = NRF52_CMD_DATA + l + raw_pkt + crc
        self.serial.write(data)

        if self.n_debug:
            print(Fore.CYAN + 'Bytes sent: ' + data.hex().upper())

        return data

    
    def send(self, scapy_pkt, print_tx=True):
        self.raw_send(raw(scapy_pkt))
        if print_tx:
            print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])

    def raw_receive(self):
        c = self.serial.read(1)
        # Receive BLE adv or channel packets
        if c == NRF52_CMD_DATA or c == NRF52_CMD_DATA_TX:
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            sz = lb | (hb << 8)
            lb = ord(self.serial.read(1))
            hb = ord(self.serial.read(1))
            evt_counter = lb | (hb << 8)
            data = bytearray(self.serial.read(sz))
            checksum = ord(self.serial.read(1))
            if (sum(data) & 0xFF) == checksum:
                # If the data received is correct
                self.event_counter = evt_counter

                if c == NRF52_CMD_DATA_TX:
                    self.sent_pkt = data

                    ret_data = None
                else:  # Received packets
                    ret_data = data

                if self.n_debug:
                    print(Fore.MAGENTA + "Received bytes: " + data.hex().upper())

                return ret_data

    def set_log_tx(self, value):
        data = NRF52_CMD_CONFIG_LOG_TX + bytearray([value])
        self.serial.write(data)
    


