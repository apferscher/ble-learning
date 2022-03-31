import sys
import constant
import resource
from BLESULConnectingStart import BLESULConnectingStart
from FailSafeLearning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from FailSafeLearning.FailSafeCacheSUL import FailSafeCacheSUL
from FailSafeLearning.LStar import run_Lstar
from aalpy.utils import visualize_automaton
from util import print_error_info

rsrc = resource.RLIMIT_DATA
soft, hard = resource.getrlimit(rsrc)
resource.setrlimit(rsrc, (1024 * 1024 * 1024 * 12, hard))

"""
this script uses the learning interface that start learning after establishing a connection. Therefore, also the input alphabet is reduced.
"""

args_len = len(sys.argv) - 1

if args_len < 2:
    sys.exit("Too few arguments provided.\nUsage: python3 ble_learning.py 'serial_port' 'advertiser_address', ['pcap- & model-filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]
learned_model_name = 'learned_model'
if args_len == 3:
    pcap_filename = sys.argv[3]
    learned_model_name = sys.argv[3]
else:
    pcap_filename = 'learning_data'

ble_sul = BLESULConnectingStart(serial_port, advertiser_address)

# enable our fail safe caching
sul = FailSafeCacheSUL(ble_sul)

# define the input alphabet
alphabet = ['length_req', 'length_rsp',  'feature_rsp', 'feature_req', 'version_req', 'mtu_req', 'pairing_req']


# define a equivalence oracle
eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=10, walk_len=10)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=False, print_level=3)

# prints number of connection and non-deterministic errors
print_error_info(ble_sul, sul)

print('-----------------------------------')
print('Reset hold time: {}'.format(round(ble_sul.waiting_time,2)))
print('-----------------------------------')

#save pcap file of sent and received packages during learning
if constant.LOG_PCAP:
    ble_sul.save_pcap(pcap_filename + '.pcap')

# visualize the automaton
visualize_automaton(learned_model, path=learned_model_name, file_type='dot')
