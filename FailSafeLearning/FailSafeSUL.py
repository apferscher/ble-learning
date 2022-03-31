from aalpy.base import SUL


class FailSafeSUL(SUL):

    def __init__(self):
        super().__init__()
        self.performed_steps_in_query = 0
