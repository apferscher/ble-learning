from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, LEShortField, LEIntField
from scapy.compat import chb
from scapy.config import conf
from scapy.layers.bluetooth4LE import BTLE


###
# The code used in this file is copied from the SweynTooth project:
# https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks
#
# Following file/class has been copied:
# -- libs/scapy/layers/bluetooth4LE.py (class NORDIC_BLE)
# -- bindings for the NORDIC_BLE packet added
#
#
# Date of copy: 08/18/2021
#
###

class NORDIC_BLE(Packet):
    """Cooked Nordic BTLE link-layer pseudoheader.
    """
    name = "BTLE Nordic info header"
    fields_desc = [
        ByteField("board", 0),
        LEShortField("payload_len", None),
        ByteField("protocol", 0),
        LEShortField("packet_counter", 0),
        ByteField("packet_id", 0),
        ByteField("packet_len", 10),
        ByteField("flags", 0),
        ByteField("channel", 0),
        ByteField("rssi", 0),
        LEShortField("event_counter", 0),
        LEIntField("delta_time", 0),
    ]

    def post_build(self, p, pay):
        if self.payload_len is None:
            p = p[:1] + chb(len(pay) + 10) + p[2:]
        return p + pay

# bindings
DLT_NORDIC_BLE	= 272
conf.l2types.register(DLT_NORDIC_BLE, NORDIC_BLE)
bind_layers(NORDIC_BLE, BTLE)