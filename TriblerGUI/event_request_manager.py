import json
from PyQt5.QtCore import QUrl, pyqtSignal
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest


class EventRequestManager(QNetworkAccessManager):
    """
    The EventRequestManager class handles the events connection over which important events in Tribler are pushed.
    """

    received_search_result_channel = pyqtSignal(object)
    received_search_result_torrent = pyqtSignal(object)
    current_event_string = ""

    def on_error(self, error):
        # TODO Martijn: do something useful here
        print "GOT EVENT ERROR"

    def on_finished(self):
        # TODO Martijn: do something useful here
        print self.reply.error()

    def on_read_data(self):
        data = self.reply.readAll()
        self.current_event_string += data
        if self.current_event_string[-1] == '\n':
            for event in self.current_event_string.split('\n'):
                if len(event) == 0:
                    continue
                json_dict = json.loads(str(event))
                if json_dict["type"] == "search_result_channel":
                    self.received_search_result_channel.emit(json_dict["event"]["result"])
                elif json_dict["type"] == "search_result_torrent":
                    self.received_search_result_torrent.emit(json_dict["event"]["result"])
            self.current_event_string = ""

    def __init__(self):
        QNetworkAccessManager.__init__(self)
        url = QUrl("http://localhost:8085/events")
        req = QNetworkRequest(url)
        self.reply = self.get(req)

        self.reply.readyRead.connect(self.on_read_data)
        self.reply.finished.connect(self.on_finished)
        self.reply.error.connect(self.on_error)
