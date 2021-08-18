import sys
import constant
from BLESUL import BLESUL
from FailSafeLearning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from FailSafeLearning.FailSafeCacheSUL import FailSafeCacheSUL
from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton
from util import print_error_info

args_len = len(sys.argv) - 1

if args_len < 2:
    sys.exit("Too few arguments provided.\nUsage: python3 ble_learning.py 'serial_port' 'advertiser_address', ['pcap_filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]

if args_len == 3:
    pcap_filename = sys.argv[3]
else:
    pcap_filename = 'learning_data'

pcap_filename += '.pcap'

ble_sul = BLESUL(serial_port, advertiser_address)

# enable our fail safe caching
sul = FailSafeCacheSUL(ble_sul)

# define the input alphabet
alphabet = ['scan_req', 'connection_req', 'length_req', 'length_rsp',  'feature_rsp', 'version_req', 'mtu_req', 'pairing_req', 'feature_req']


# define a equivalence oracle
eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=10, walk_len=10)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=False)

# prints number of connection and non-deterministic errors
print_error_info(ble_sul, sul)

#save pcap file of sent and received packages during learning
if constant.LOG_PCAP:
    ble_sul.save_pcap(pcap_filename)

# visualize the automaton
visualize_automaton(learned_model, file_type='dot')