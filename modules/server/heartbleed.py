from modules.server.testssl_base import Testssl_base


class Heartbleed(Testssl_base):

    """
    Analysis of the heartbleed testssl results
    """

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-H"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["heartbleed"])
