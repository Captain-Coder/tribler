# coding=utf-8
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QLabel, QStatusBar
from TriblerGUI.tribler_request_manager import TriblerRequestManager
from TriblerGUI.utilities import format_speed


class TriblerStatusBar(QStatusBar):
    """
    This class manages the status bar at the bottom of the screen.
    """

    def __init__(self, parent):
        super(QStatusBar, self).__init__(parent)

        self.speed_label = QLabel(self)
        self.speed_label.setStyleSheet("color: #eee")
        self.set_speeds(0, 0)
        self.speed_label.setAlignment(Qt.AlignRight)

        self.multichain_label = QLabel(self)
        self.multichain_label.setStyleSheet("color: #eee")
        self.set_multichain_stats(0, 0)
        self.multichain_label.setAlignment(Qt.AlignRight)

        self.addWidget(self.multichain_label, 1)
        self.addWidget(self.speed_label, 1)

        self.start_loading_multichain_stats()

    def start_loading_multichain_stats(self):
        self.multichain_stats_timer = QTimer()
        self.multichain_stats_timer.timeout.connect(self.load_multichain_stats)
        self.multichain_stats_timer.start(10 * 1000)

    def stop_loading_multichain_stats(self):
        self.multichain_stats_timer.stop()

    def load_multichain_stats(self):
        self.request_mgr = TriblerRequestManager()
        self.request_mgr.perform_request("multichain/statistics", self.on_received_multichain_stats)

    def on_received_multichain_stats(self, multichain):
        if multichain and 'statistics' in multichain:
            self.set_multichain_stats(multichain['statistics']['self_total_down_mb']*1024*1024,
                                      multichain['statistics']['self_total_up_mb']*1024*1024)

    def set_speeds(self, download, upload):
        self.speed_label.setText("↓ %s  ↑ %s" % (format_speed(download), format_speed(upload)))

    def set_multichain_stats(self, downloaded, uploaded):
        total = downloaded + uploaded
        balance = uploaded - downloaded
        self.multichain_label.setText("Total %s  Balance %s" % (format_speed(total), format_speed(balance)))
