import sys
import constant
import resource
from BLESULPairing import BLESULPairing
from FailSafeLearning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe
from FailSafeLearning.FailSafeCacheSUL import FailSafeCacheSUL
from FailSafeLearning.LStar import run_Lstar
from aalpy.utils import visualize_automaton
from util import print_error_info

rsrc = resource.RLIMIT_DATA
soft, hard = resource.getrlimit(rsrc)
resource.setrlimit(rsrc, (1024 * 1024 * 1024 * 12, hard))

args_len = len(sys.argv) - 1

if args_len < 2:
    sys.exit("Too few arguments provided.\nUsage: python3 ble_learning.py 'serial_port' 'advertiser_address', ['pcap- & model-filename']")

serial_port = sys.argv[1]
advertiser_address = sys.argv[2]

physical_reset_str = ''
physical_reset = False

if args_len == 3:
    filename = sys.argv[3]
else:
    filename = 'learning_data'

pcap_filename = filename + '.pcap'

ble_sul = BLESULPairing(serial_port, advertiser_address, physical_reset=True)

# enable our fail safe caching
sul = FailSafeCacheSUL(ble_sul)

alphabet = ['legacy_pairing_req', 'sm_confirm', 'sm_random', 'll_enc_request', 'll_start_enc_response']


# define a equivalence oracle
eq_oracle = StatePrefixOracleFailSafe(alphabet, sul, walks_per_state=10, walk_len=10)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=False, print_level=3)

# prints number of connection and non-deterministic errors
print_error_info(ble_sul, sul, eq_oracle)

print('Reset time for connection errors: {}'.format(ble_sul.connection_physical_reset_time))
print('Resets due to connection errors: {}'.format(ble_sul.connection_physical_reset))

#save pcap file of sent and received packages during learning
if constant.LOG_PCAP:
    ble_sul.save_pcap(pcap_filename)

# visualize the automaton
visualize_automaton(learned_model, path=filename, file_type='dot')
