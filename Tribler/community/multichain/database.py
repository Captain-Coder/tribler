""" This file contains everything related to persistence for MultiChain.
"""
from os import path
from hashlib import sha256

from Tribler.dispersy.database import Database
from Tribler.community.multichain.conversion import encode_block, encode_block_requester_half, encode_block_crawl,\
    EMPTY_HASH

# ID of the first block of the chain.
GENESIS_ID = '0' * 20

DATABASE_DIRECTORY = path.join(u"sqlite")
""" Path to the database location + dispersy._workingdirectory"""
DATABASE_PATH = path.join(DATABASE_DIRECTORY, u"multichain.db")
""" Version to keep track if the db schema needs to be updated."""
LATEST_DB_VERSION = 1
""" Schema for the MultiChain DB."""
schema = u"""
CREATE TABLE IF NOT EXISTS multi_chain(
 public_key_requester		TEXT NOT NULL,
 public_key_responder		TEXT NOT NULL,
 up                         INTEGER NOT NULL,
 down                       INTEGER NOT NULL,

 total_up_requester         UNSIGNED BIG INT NOT NULL,
 total_down_requester       UNSIGNED BIG INT NOT NULL,
 sequence_number_requester  INTEGER NOT NULL,
 previous_hash_requester	TEXT NOT NULL,
 signature_requester		TEXT NOT NULL,
 hash_requester		        TEXT PRIMARY KEY,

 total_up_responder         UNSIGNED BIG INT NOT NULL,
 total_down_responder       UNSIGNED BIG INT NOT NULL,
 sequence_number_responder  INTEGER NOT NULL,
 previous_hash_responder	TEXT NOT NULL,
 signature_responder		TEXT NOT NULL,
 hash_responder		        TEXT NOT NULL,

 insert_time                TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
 );

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '""" + str(LATEST_DB_VERSION) + u"""');
"""


class MultiChainDB(Database):
    """
    Persistence layer for the MultiChain Community.
    Connection layer to SQLiteDB.
    Ensures a proper DB schema on startup.
    """

    def __init__(self, dispersy, working_directory):
        """
        Sets up the persistence layer ready for use.
        :param dispersy: Dispersy stores the PK.
        :param working_directory: Path to the working directory
        that will contain the the db at working directory/DATABASE_PATH
        :return:
        """
        super(MultiChainDB, self).__init__(path.join(working_directory, DATABASE_PATH))
        self._dispersy = dispersy
        self.open()

    def add_block(self, block):
        """
        Persist a block
        :param block: The data that will be saved.
        """
        data = (buffer(block.public_key_requester), buffer(block.public_key_responder), block.up, block.down,
                block.total_up_requester, block.total_down_requester,
                block.sequence_number_requester, buffer(block.previous_hash_requester),
                buffer(block.signature_requester), buffer(block.hash_requester),
                block.total_up_responder, block.total_down_responder,
                block.sequence_number_responder, buffer(block.previous_hash_responder),
                buffer(block.signature_responder), buffer(block.hash_responder))

        self.execute(
            u"INSERT INTO multi_chain (public_key_requester, public_key_responder, up, down, "
            u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, "
            u"signature_requester, hash_requester, "
            u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, "
            u"signature_responder, hash_responder) "
            u"VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            data)

    def update_block_with_responder(self, block):
        """
        Update an existing block
        :param block: The data that will be saved.
        """
        data = (
                block.total_up_responder, block.total_down_responder,
                block.sequence_number_responder, buffer(block.previous_hash_responder),
                buffer(block.signature_responder), buffer(block.hash_responder), buffer(block.hash_requester))

        self.execute(
            u"UPDATE multi_chain "
            u"SET total_up_responder = ?, total_down_responder = ?, "
            u"sequence_number_responder = ?, previous_hash_responder = ?, "
            u"signature_responder = ?, hash_responder = ? "
            u"WHERE hash_requester = ?",
            data)

    def get_latest_hash(self, public_key):
        """
        Get the relevant hash of the latest block in the chain for a specific public key.
        Relevant means the hash_requester if the last block was a request,
        hash_responder if the last block was a response.
        :param public_key: The public_key for which the latest hash has to be found.
        :return: the relevant hash
        """
        public_key = buffer(public_key)
        db_query = u"SELECT block_hash, MAX(sequence_number) FROM (" \
                   u"SELECT hash_requester AS block_hash, sequence_number_requester AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_requester = ? "\
                   u"UNION "\
                   u"SELECT hash_responder AS block_hash, sequence_number_responder AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_responder = ?)"

        db_result = self.execute(db_query, (public_key, public_key)).fetchone()[0]

        return str(db_result) if db_result else None

    def get_latest_block(self, public_key):
        return self.get_by_hash(self.get_latest_hash(public_key))

    def get_by_hash_requester(self, hash_requester):
        """
        Returns a block saved in the persistence
        :param hash_requester: The hash_requester of the block that needs to be retrieved.
        :return: The block that was requested or None
        """
        db_query = u"SELECT public_key_requester, public_key_responder, up, down, " \
                   u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, " \
                   u"signature_requester, hash_requester, " \
                   u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, " \
                   u"signature_responder, hash_responder, insert_time " \
                   u"FROM `multi_chain` WHERE hash_requester = ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(hash_requester),)).fetchone()
        # Create a DB Block or return None
        return self._create_database_block(db_result)

    def get_by_hash(self, hash):
        """
        Returns a block saved in the persistence, based on a hash that can be either hash_requester or hash_responder
        :param hash: The hash of the block that needs to be retrieved.
        :return: The block that was requested or None
        """
        db_query = u"SELECT public_key_requester, public_key_responder, up, down, " \
                   u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, " \
                   u"signature_requester, hash_requester, " \
                   u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, " \
                   u"signature_responder, hash_responder, insert_time " \
                   u"FROM `multi_chain` WHERE hash_requester = ? OR hash_responder = ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(hash), buffer(hash))).fetchone()
        # Create a DB Block or return None
        return self._create_database_block(db_result)

    def get_by_public_key_and_sequence_number(self, public_key, sequence_number):
        """
        Returns a block saved in the persistence.
        :param public_key: The public key corresponding to the block
        :param sequence_number: The sequence number corresponding to the block.
        :return: The block that was requested or None"""
        db_query = u"SELECT public_key_requester, public_key_responder, up, down, " \
                   u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, " \
                   u"signature_requester, hash_requester, " \
                   u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, " \
                   u"signature_responder, hash_responder, insert_time " \
                   u"FROM (" \
                   u"SELECT *, sequence_number_requester AS sequence_number, " \
                   u"public_key_requester AS pk FROM `multi_chain` " \
                   u"UNION " \
                   u"SELECT *, sequence_number_responder AS sequence_number," \
                   u"public_key_responder AS pk FROM `multi_chain`) " \
                   u"WHERE sequence_number = ? AND pk = ? LIMIT 1"
        db_result = self.execute(db_query, (sequence_number, buffer(public_key))).fetchone()
        # Create a DB Block or return None
        return self._create_database_block(db_result)

    def get_blocks_since(self, public_key, sequence_number, limit=100):
        """
        Returns database blocks with sequence number higher than or equal to sequence_number, at most 100 results
        :param public_key: The public key corresponding to the member id
        :param sequence_number: The linear block number
        :param limit: Optional limit on the number of blocks to fetch. Defaults to 100
        :return A list of DB Blocks that match the criteria
        """
        db_query = u"SELECT public_key_requester, public_key_responder, up, down, " \
                   u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, " \
                   u"signature_requester, hash_requester, " \
                   u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, " \
                   u"signature_responder, hash_responder, insert_time " \
                   u"FROM (" \
                   u"SELECT *, sequence_number_requester AS sequence_number," \
                   u" public_key_requester AS public_key FROM `multi_chain` " \
                   u"UNION " \
                   u"SELECT *, sequence_number_responder AS sequence_number," \
                   u" public_key_responder AS public_key FROM `multi_chain`) " \
                   u"WHERE sequence_number >= ? AND public_key = ? " \
                   u"ORDER BY sequence_number ASC "\
                   u"LIMIT ?"
        db_result = self.execute(db_query, (sequence_number, buffer(public_key), limit)).fetchall()
        return [self._create_database_block(db_item) for db_item in db_result]

    def get_blocks_until(self, public_key, sequence_number, limit=100):
        """
        Returns database blocks with sequence number lower than or equal to sequence_number, at most 100 results
        :param public_key: The public key corresponding to the member id
        :param sequence_number: The linear block number
        :param limit: Optional limit on the number of blocks to fetch. Defaults to 100
        :return A list of DB Blocks that match the criteria
        """
        db_query = u"SELECT public_key_requester, public_key_responder, up, down, " \
                   u"total_up_requester, total_down_requester, sequence_number_requester, previous_hash_requester, " \
                   u"signature_requester, hash_requester, " \
                   u"total_up_responder, total_down_responder, sequence_number_responder, previous_hash_responder, " \
                   u"signature_responder, hash_responder, insert_time " \
                   u"FROM (" \
                   u"SELECT *, sequence_number_requester AS sequence_number, " \
                   u" public_key_requester AS public_key FROM `multi_chain` " \
                   u"UNION " \
                   u"SELECT *, sequence_number_responder AS sequence_number, " \
                   u" public_key_responder AS public_key FROM `multi_chain`) " \
                   u"WHERE sequence_number <= ? AND public_key = ? " \
                   u"ORDER BY sequence_number DESC "\
                   u"LIMIT ?"
        db_result = self.execute(db_query, (sequence_number, buffer(public_key), limit)).fetchall()
        return [self._create_database_block(db_item) for db_item in db_result]

    def _create_database_block(self, db_result):
        """
        Create a Database block or return None.
        :param db_result: The DB_result with the DatabaseBlock or None
        :return: DatabaseBlock if db_result else None
        """
        if db_result:
            return DatabaseBlock(db_result)
        else:
            return None

    def get_all_hash_requester(self):
        """
        Get all the hash_requester saved in the persistence layer.
        :return: list of hash_requester.
        """
        db_result = self.execute(u"SELECT hash_requester FROM multi_chain").fetchall()
        # Unpack the db_result tuples and decode the results.
        return [str(x[0]) for x in db_result]

    def contains(self, hash_requester):
        """
        Check if a block is existent in the persistence layer.
        :param hash_requester: The hash_requester that is queried
        :return: True if the block exists, else false.
        """
        db_query = u"SELECT hash_requester FROM multi_chain WHERE hash_requester == ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(hash_requester),)).fetchone()
        return db_result is not None

    def get_latest_sequence_number(self, public_key):
        """
        Return the latest sequence number known for this public_key.
        If no block for the pk is know returns -1.
        :param public_key: Corresponding public key
        :return: sequence number (integer) or -1 if no block is known
        """
        public_key = buffer(public_key)
        db_query = u"SELECT MAX(sequence_number) FROM (" \
                   u"SELECT sequence_number_requester AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_requester == ? UNION " \
                   u"SELECT sequence_number_responder AS sequence_number " \
                   u"FROM multi_chain WHERE public_key_responder = ? )"
        db_result = self.execute(db_query, (public_key, public_key)).fetchone()[0]
        return db_result if db_result is not None else -1

    def get_total(self, public_key):
        """
        Return the latest (total_up, total_down) known for this node.
        if no block for the pk is know returns (-1,-1)
        :param public_key: public_key of the node
        :return: (total_up (int), total_down (int)) or (-1, -1) if no block is known.
        """
        public_key = buffer(public_key)
        db_query = u"SELECT total_up, total_down, MAX(sequence_number) FROM (" \
                   u"SELECT total_up_requester AS total_up, total_down_requester AS total_down, " \
                   u"sequence_number_requester AS sequence_number FROM multi_chain " \
                   u"WHERE public_key_requester == ? UNION " \
                   u"SELECT total_up_responder AS total_up, total_down_responder AS total_down, " \
                   u"sequence_number_responder AS sequence_number FROM multi_chain WHERE public_key_responder = ? )" \
                   u"LIMIT 1"
        db_result = self.execute(db_query, (public_key, public_key)).fetchone()
        return (db_result[0], db_result[1]) if db_result[0] is not None and db_result[1] is not None \
            else (-1, -1)

    def validate(self, public_key, seq, up, down, t_up, t_down, prev_hash):
        """
        Check if block parameters violate what we know about a certain member
        :param public_key: The member information to check
        :param seq: The block sequence number
        :param up: Uploaded by the member
        :param down: Downloaded by the member
        :param t_up: Total uploaded by the member
        :param t_down: Total downloaded by the member
        :param prev_hash: The previous hash of the block being checked
        :return: "valid" if the values do not violate the rules,
                 "partial-next" if the values do not violate, but there are unknown blocks in the future
                 "partial-prev" if the values do not violate, but there are unknown blocks in the past
                 "partial" if the values do not violate, but there are unknown blocks on either side.
                 "invalid" if the values violate any of the rules,
                 "no-data" if there is not enough information known about the member to validate
        """
        blk = self.get_by_public_key_and_sequence_number(public_key, seq)
        if blk and (blk.public_key_requester == blk.public_key_responder or
                blk.public_key_requester == public_key and (
                                blk.up != up or blk.down != down or
                                blk.sequence_number_requester != seq or
                                blk.total_up_requester != t_up or
                                blk.total_down_requester != t_down or
                                blk.previous_hash_requester != prev_hash
                            ) or
                blk.public_key_responder == public_key and (
                                blk.up != down or blk.down != up or
                                blk.sequence_number_responder != seq or
                                blk.total_up_responder != t_up or
                                blk.total_down_responder != t_down or
                                blk.previous_hash_responder != prev_hash
                            )):
            # the block exists in the database but the values do not agree
            return "invalid"

        if seq == 1 and prev_hash != GENESIS_ID:
            return "invalid"
        elif seq != 1 and prev_hash == GENESIS_ID:
            return "invalid"

        prev_blk = (self.get_blocks_until(public_key, seq - 1, limit=1) or [None])[0]
        next_blk = (self.get_blocks_since(public_key, seq + 1, limit=1) or [None])[0]
        result = "valid"
        if not prev_blk and not next_blk:
            # No blocks found, there is no info to base on
            result = "no-info"
        elif not next_blk:
            # The next block does not exist in the database, at best our result can now be partial w.r.t. next
            result = "partial-next"
            if prev_blk.public_key_requester == public_key and prev_blk.sequence_number_requester != seq - 1 or \
                prev_blk.public_key_responder == public_key and prev_blk.sequence_number_responder != seq - 1:
                # If both sides are unknown or non-contiguous return a full partial result.
                result = "partial"
        elif not prev_blk and seq != 1:
            # The previous block does not exist in the database, at best our result can now be partial w.r.t. prev
            result = "partial-prev"
            if next_blk.public_key_requester == public_key and next_blk.sequence_number_requester != seq + 1 or \
                next_blk.public_key_responder == public_key and next_blk.sequence_number_responder != seq + 1:
                # If both sides are unknown or non-contiguous return a full partial result.
                result = "partial"

        if prev_blk and (
                (prev_blk.public_key_requester == public_key and (prev_blk.total_up_requester + up > t_up or
                        prev_blk.total_down_requester + down > t_down or
                        (prev_blk.sequence_number_requester == seq - 1 and prev_blk.hash_requester != prev_hash)))
             or (prev_blk.public_key_responder == public_key and (prev_blk.total_up_responder + up > t_up or
                        prev_blk.total_down_responder + down > t_down or
                        (prev_blk.sequence_number_responder == seq - 1 and prev_blk.hash_responder != prev_hash)))):
            result = "invalid"

        if next_blk and (
                (next_blk.public_key_requester == public_key and (t_up + next_blk.up > next_blk.total_up_requester or
                        t_down + next_blk.down > next_blk.total_down_requester))
             or (next_blk.public_key_responder == public_key and (t_up + next_blk.down > next_blk.total_up_responder or
                        t_down + next_blk.up > next_blk.total_down_responder))):
            result = "invalid"

        return result

    def open(self, initial_statements=True, prepare_visioning=True):
        return super(MultiChainDB, self).open(initial_statements, prepare_visioning)

    def close(self, commit=True):
        return super(MultiChainDB, self).close(commit)

    def check_database(self, database_version):
        """
        Ensure the proper schema is used by the database.
        :param database_version: Current version of the database.
        :return:
        """
        assert isinstance(database_version, unicode)
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version = int(database_version)

        if database_version < 1:
            self.executescript(schema)
            self.commit()

        return LATEST_DB_VERSION

class DatabaseBlock:
    """ DataClass for a multichain block. """

    def __init__(self, data):
        """ Create a block from data """
        """ Common part """
        self.public_key_requester = str(data[0])
        self.public_key_responder = str(data[1])
        self.up = data[2]
        self.down = data[3]
        """ Requester part """
        self.total_up_requester = data[4]
        self.total_down_requester = data[5]
        self.sequence_number_requester = data[6]
        self.previous_hash_requester = str(data[7])
        self.signature_requester = str(data[8])
        self.hash_requester = str(data[9])
        """ Responder part """
        self.total_up_responder = data[10]
        self.total_down_responder = data[11]
        self.sequence_number_responder = data[12]
        self.previous_hash_responder = str(data[13])
        self.signature_responder = str(data[14])
        self.hash_responder = str(data[15])

        self.insert_time = data[16]

    @classmethod
    def from_signature_response_message(cls, message):
        payload = message.payload
        requester = message.authentication.signed_members[0]
        responder = message.authentication.signed_members[1]
        return cls((requester[1].public_key, responder[1].public_key, payload.up, payload.down,
                    payload.total_up_requester, payload.total_down_requester,
                    payload.sequence_number_requester, payload.previous_hash_requester,
                    requester[0], sha256(encode_block_requester_half(payload, requester[1].public_key,
                                                                     responder[1].public_key, requester[0])).digest(),
                    payload.total_up_responder, payload.total_down_responder,
                    payload.sequence_number_responder, payload.previous_hash_responder,
                    responder[0], sha256(encode_block(payload, requester, responder)).digest(),
                    None))

    @classmethod
    def from_signature_request_message(cls, message):
        payload = message.payload
        requester = message.authentication.signed_members[0]
        responder = message.authentication.signed_members[1]
        return cls((requester[1].public_key, responder[1].public_key, payload.up, payload.down,
                    payload.total_up_requester, payload.total_down_requester,
                    payload.sequence_number_requester, payload.previous_hash_requester,
                    requester[0], sha256(encode_block_requester_half(payload, requester[1].public_key,
                                                                     responder[1].public_key, requester[0])).digest(),
                    -1, -1,
                    -1, EMPTY_HASH,
                    "", EMPTY_HASH,
                    None))

    @classmethod
    def from_block_response_message(cls, message, requester, responder):
        payload = message.payload
        return cls((requester.public_key, responder.public_key, payload.up, payload.down,
                    payload.total_up_requester, payload.total_down_requester,
                    payload.sequence_number_requester, payload.previous_hash_requester,
                    payload.signature_requester,
                    sha256(encode_block_requester_half(payload, payload.public_key_requester,
                                                       payload.public_key_responder,
                                                       payload.signature_requester)).digest(),
                    payload.total_up_responder, payload.total_down_responder,
                    payload.sequence_number_responder, payload.previous_hash_responder,
                    payload.signature_responder, sha256(encode_block_crawl(payload)).digest(),
                    None))

    def to_payload(self):
        """
        :return: (tuple) corresponding to the payload data in a Signature message.
        """
        return (self.up, self.down,
                self.total_up_requester, self.total_down_requester,
                self.sequence_number_requester, self.previous_hash_requester,
                self.total_up_responder, self.total_down_responder,
                self.sequence_number_responder, self.previous_hash_responder,
                self.public_key_requester, self.signature_requester,
                self.public_key_responder, self.signature_responder)
