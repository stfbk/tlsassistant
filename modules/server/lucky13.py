from modules.server.testssl_base import Testssl_base


class Lucky13(Testssl_base):

    """
    Analysis of the lucky13 testssl results
    """

    # to override
    def _set_arguments(self):
        """
        Sets the arguments for the testssl command
        """
        self._arguments = ["-L"]

    # to override
    def _worker(self, results):
        """
        The worker method, which runs the testssl command

        :param results: dict
        :return: dict
        :rtype: dict
        """
        return self._obtain_results(results, ["LUCKY13"])
