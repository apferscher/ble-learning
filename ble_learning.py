from BLESUL import BLESUL
from FailSafeLearning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from FailSafeLearning.FailSafeCacheSUL import FailSafeCacheSUL
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton
from util import print_error_info

serial_port = '/dev/tty.usbmodem141101'
#advertiser_address = 'CC:78:AB:71:5C:85' # TI LAUNCHXL-CC2650
#advertiser_address = '0C:61:CF:A0:95:8F' # TI LAUNCHXL-CC264CR2
#advertiser_address = 'f6:a8:63:cd:b7:d4' # dwm 1001
#advertiser_address = 'dc:a6:32:4b:59:61' # raspberry pi 4
advertiser_address = '00:A0:50:00:00:03' # Cypress CY8CPROTO-063

#file = 'TI-LAUNCHXL-CC2650'
#file = 'TI-LAUNCHXL-CC264CR2-without-length-request'
#file = 'dwm-1001'
#file = 'raspberrypi-4'
file = 'Cypress-CY8CPROTO-063'

ble_sul = BLESUL(serial_port, advertiser_address)

# enable our fail safe caching
sul = FailSafeCacheSUL(ble_sul)

# define the input alphabet
alphabet = ['scan_req', 'connection_req', 'length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req', 'feature_req']

#alphabet = ['scan_req', 'connection_req', 'feature_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req']


# define a equivalence oracle
eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=10, walk_len=10)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=False)
# visualize the automaton

print_error_info(ble_sul, sul)

visualize_automaton(learned_model, path=file, file_type='dot')