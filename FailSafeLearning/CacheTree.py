from statistics import mode
from FailSafeLearning.Errors import NonDeterministicError, RepeatedNonDeterministicError, TableError

class Node(object):
    def __init__(self, value=None):
        self.value = value
        self.children = {}
        self.nonDetCache = []
        self.updateDetCache = False
        self.nonDetUpdated = False


class CacheTree:
    """
    Tree in which all membership queries and corresponding outputs/values are stored. Membership queries update the tree
    and while updating, check if determinism is maintained.
    Root node corresponds to the initial state, and from that point on, for every new input/output pair, a new child is
    created where the output is the value of the child, and the input is the transition leading from the parent to the
    child.
    """

    def __init__(self, max_cache_buffer_size):
        self.root_node = Node()
        self.curr_node = None
        self.non_det_node = None
        self.inputs = []
        self.outputs = []
        self.non_corresponding_outputs = 0
        self.values_updated = 0
        self.cached_non_deterministic_query = 0
        self.max_cache_buffer_size = max_cache_buffer_size

    def reset(self):
        self.curr_node = self.root_node
        self.inputs = []
        self.outputs = []

    def step_in_cache(self, inp, out):
        """
        Preform a step in the cache. If output exist for the current state, and is not the same as `out`, throw
        the non-determinism violation error and abort learning.
        Args:

            inp: input
            out: output

        """
        self.inputs.append(inp)
        self.outputs.append(out)
        if inp is None:
            self.root_node.value = out
            return
            
        if inp not in self.curr_node.children.keys():
            node = Node(out)
            node.updateDetCache = True
            self.curr_node.children[inp] = node
        else:
            node = self.curr_node.children[inp]
            if node.value != out:
                self.non_corresponding_outputs += 1
                if not node.nonDetUpdated:
                    node.updateDetCache = True
            if node.updateDetCache:
                node.nonDetUpdated = True
                if len(node.nonDetCache) < self.max_cache_buffer_size:
                    node.nonDetCache.append(out)
                    self.cached_non_deterministic_query += 1
                    if len(node.nonDetCache) == self.max_cache_buffer_size:
                        node.updateDetCache = False
                        most_frequent_out = mode(node.nonDetCache)
                        if most_frequent_out != node.value:
                            self.values_updated += 1
                            print("-"*80)
                            print("Old value: " + node.value)
                            print("New value: " + most_frequent_out)
                            print("Cached values: " + str(node.nonDetCache))
                            print("-"*80)
                            node.value = most_frequent_out
                            raise TableError()
                    else: 
                       raise NonDeterministicError() 
                else: 
                    raise NonDeterministicError()
            if node.value != out and node.nonDetUpdated and not node.updateDetCache:
                # repeat query
                expected_seq = list(self.outputs[:-1])
                expected_seq.append(node.value)
                msg = f'Non-determinism detected.\n' \
                      f'Error inserting: {self.inputs}\n' \
                      f'Conflict detected: {node.value} vs {out}\n' \
                      f'Expected Output: {expected_seq}\n' \
                      f'Received output: {self.outputs}'
                print(msg)
                self.non_det_node = node
                raise RepeatedNonDeterministicError()
        self.curr_node = node

    def in_cache(self, input_seq: tuple):
        """
        Check if the result of the membership query for input_seq is cached is in the tree. If it is, return the
        corresponding output sequence.

        Args:

            input_seq: corresponds to the membership query

        Returns:

            outputs associated with inputs if it is in the query, None otherwise

        """
        curr_node = self.root_node

        output_seq = []
        for letter in input_seq:
            if letter in curr_node.children.keys():
                curr_node = curr_node.children[letter]
                output_seq.append(curr_node.value)
            else:
                return None

        return output_seq
