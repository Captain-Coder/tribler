import os
from time import sleep

from Tribler.TrackerChecking.TorrentChecking import TorrentChecking

from Tribler.Core.TorrentDef import TorrentDef
from Tribler.Core.CacheDB.SqliteCacheDBHandler import TorrentDBHandler, \
    MyPreferenceDBHandler

from Tribler.Test.test_as_server import BASE_DIR, TestAsServer


class TestTorrentChecking(TestAsServer):

    def setUp(self):
        TestAsServer.setUp(self)

        self.tdb = TorrentDBHandler.getInstance()
        self.tdb.mypref_db = MyPreferenceDBHandler.getInstance()

        self.torrentChecking = TorrentChecking.getInstance()
        self.torrentChecking.setTorrentSelectionInterval(5)

    def setUpPreSession(self):
        TestAsServer.setUpPreSession(self)
        self.config.set_torrent_checking(True)
        self.config.set_megacache(True)
        self.config.set_torrent_checking_period(5.0)

    # ------------------------------------------------------------
    # Unit Test for TorrentChecking thread.
    # ------------------------------------------------------------
    def test_torrent_checking(self):
        tdef = TorrentDef.load(os.path.join(BASE_DIR, "data", "Pioneer.One.S01E06.720p.x264-VODO.torrent"))
        tdef.set_tracker("http://95.211.198.141:2710/announce")
        tdef.metainfo_valid = True

        self.tdb.addExternalTorrent(tdef)
        sleep(15)

        torrent = self.tdb.getTorrent(tdef.get_infohash())
        self._logger.debug('got torrent %s', torrent)

        num_seeders = torrent['num_seeders']
        num_leechers = torrent['num_leechers']
        assert num_leechers >= 0 or num_seeders >= 0, (num_leechers, num_seeders)
