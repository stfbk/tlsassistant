from modules.server.testssl_base import Testssl_base


class Robot(Testssl_base):

    # to override
    def _set_arguments(self):
        self._arguments = ["-BB"]

    # to override
    def _worker(self, results):
        return self._obtain_results(results, ["ROBOT"])

    def _set_mitigation(self):
        pass
        # todo : decide how to save mitigations
