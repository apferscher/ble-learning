from urllib.request import CacheFTPHandler
from BLESUL import BLESUL
from FailSafeLearning.FailSafeCacheSUL import FailSafeCacheSUL
from FailSafeLearning.StatePrefixEqOracleFailSafe import StatePrefixOracleFailSafe

def get_error_info(ble: BLESUL, cache: FailSafeCacheSUL, eq_oracle: StatePrefixOracleFailSafe):
    """
    Create error statistics.
    """

    error_info = {
        'replaced_values' : cache.cache.values_updated,
        'repeated_cached_queries': cache.cache.cached_non_deterministic_query,
        'non_det_output': cache.cache.non_corresponding_outputs,
        'non_det_query': cache.non_det_query_counter,
        'non_det_step': cache.non_det_step_counter,
        'connection_error': ble.connection_error_counter,
        'mq_reset_time': cache.reset_time,
        'cq_reset_time': eq_oracle.reset_time,
        'mq_physical_resets': cache.physical_reset,
        'cq_physical_resets': eq_oracle.physical_reset,

    }
    return error_info


def print_error_info(ble: BLESUL, cache: FailSafeCacheSUL, eq_oracle: StatePrefixOracleFailSafe):
    """
    Print error statistics.
    """
    error_info = get_error_info(ble,cache, eq_oracle)
  
    print('-----------------------------------')
    print('Connection errors:  {}'.format(error_info['connection_error']))
    print('Cached values updated: {}'.format(error_info['replaced_values']))
    print('Queries performed to determine correct output (before update): {}'.format(error_info['repeated_cached_queries']))
    print('Non-determinism in learning (before update): {}'.format(error_info['non_det_output']))
    print('Non-determinism in learning (after update): {}'.format(error_info['non_det_query']))
    print('Non-determinism in equivalence check (after update): {}'.format(error_info['non_det_step']))
    print('Physical resets during membership queries: {}'.format(error_info['mq_physical_resets']))
    print('Physical resets during conformance queries: {}'.format(error_info['cq_physical_resets']))
    print('Reset time during membership queries: {}'.format(error_info['mq_reset_time']))
    print('Reset time  during conformance queries: {}'.format(error_info['cq_reset_time']))
    print('-----------------------------------')