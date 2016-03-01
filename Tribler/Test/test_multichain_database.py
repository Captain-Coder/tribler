import unittest
import datetime
import os
from math import pow
import random

from hashlib import sha1

from Tribler.dispersy.crypto import ECCrypto

from Tribler.Test.test_multichain_utilities import TestBlock, MultiChainTestCase
from Tribler.community.multichain.database import MultiChainDB
from Tribler.community.multichain.database import DATABASE_DIRECTORY
from Tribler.community.multichain.community import GENESIS_ID

class TestDatabase(MultiChainTestCase):
    """
    Tests the Database for MultiChain community.
    Also tests integration with Dispersy.
    This integration slows down the tests,
    but can probably be removed and a Mock Dispersy could be used.
    """

    class MockDispersy:
        """
        Mock Dispersy for testing the Database.
        This Mock Dispersy saves pk and their related mids.
        """

        class MockMember:

            def __init__(self, mid):
                self.public_key = mid

        def __init__(self):
            self.db = {}

        def get_member(self, public_key='', mid=''):
            if public_key:
                self.db[mid] = public_key
            elif mid:
                return self.MockMember(self.db[mid])

    def __init__(self, *args, **kwargs):
        super(TestDatabase, self).__init__(*args, **kwargs)

    def setUp(self, **kwargs):
        super(TestDatabase, self).setUp()
        path = os.path.join(self.getStateDir(), DATABASE_DIRECTORY)
        if not os.path.exists(path):
            os.makedirs(path)

    def setup_validate(self, db, dispersy):
        block1 = TestBlock()
        block1.sequence_number_requester = 0
        block1.sequence_number_responder = 0
        block1.previous_hash_requester = GENESIS_ID
        block1.previous_hash_responder = GENESIS_ID
        block1.total_up_requester = block1.up
        block1.total_down_requester = block1.down
        block1.total_up_responder = block1.down
        block1.total_down_responder = block1.up
        block2 = TestBlock(previous=block1)
        block3 = TestBlock(previous=block2)
        block4 = TestBlock()
        return block1, block2, block3, block4

    def validate_block(self, db, block):
        result_a = db.validate(block.public_key_requester, block.sequence_number_requester, block.up, block.down, block.total_up_requester, block.total_down_requester, block.previous_hash_requester)
        result_b = db.validate(block.public_key_responder, block.sequence_number_responder, block.down, block.up, block.total_up_responder, block.total_down_responder, block.previous_hash_responder)
        return result_a, result_b

    def test_add_block(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        # Act
        db.add_block(block1)
        # Assert
        result = db.get_by_hash_requester(block1.hash_requester)
        self.assertEqual_block(block1, result)

    def test_get_by_hash(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        # Act
        db.add_block(block1)
        # Assert
        result1 = db.get_by_hash_requester(block1.hash_requester)
        result2 = db.get_by_hash(block1.hash_requester)
        result3 = db.get_by_hash(block1.hash_responder)
        self.assertEqual_block(block1, result1)
        self.assertEqual_block(block1, result2)
        self.assertEqual_block(block1, result3)


    def test_add_two_blocks(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        block2 = TestBlock()
        # Act
        db.add_block(block1)
        db.add_block(block2)
        # Assert
        result = db.get_by_hash_requester(block2.hash_requester)
        self.assertEqual_block(block2, result)

    def test_get_block_non_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        # Act
        result = db.get_by_hash_requester(block1.hash_requester)
        # Assert
        self.assertEqual(None, result)

    def test_contains_block_id_positive(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block = TestBlock()
        # Act
        db.add_block(block)
        # Assert
        self.assertTrue(db.contains(block.hash_requester))

    def test_contains_block_id_negative(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        # Act & Assert
        self.assertFalse(db.contains("NON EXISTING ID"))

    def test_get_latest_sequence_number_not_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number("NON EXISTING KEY"), -1)

    def test_get_latest_sequence_number_public_key_requester(self):

        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_responder = block1.public_key_requester
        block2.sequence_number_responder = block1.sequence_number_requester - 5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number(block1.public_key_requester),
                          block1.sequence_number_requester)

    def test_get_latest_sequence_number_public_key_responder(self):
        # Arrange
        # Make sure that there is a requester block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder - 5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number(block1.public_key_responder),
                          block1.sequence_number_responder)

    def test_get_previous_id_not_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        # Act & Assert
        self.assertEquals(db.get_latest_hash("NON EXISTING KEY"), None)

    def test_get_previous_hash_of_requester(self):
        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_responder = block1.public_key_requester
        block2.sequence_number_responder = block1.sequence_number_requester + 1
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_hash(block2.public_key_responder), block2.hash_responder)

    def test_get_previous_hash_of_responder(self):
        # Arrange
        # Make sure that there is a requester block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder + 1
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_hash(block2.public_key_requester), block2.hash_requester)

    def test_get_by_sequence_number_by_mid_not_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        # Act & Assert
        self.assertEquals(db.get_by_public_key_and_sequence_number("NON EXISTING KEY", 0), None)

    def test_get_by_public_key_and_sequence_number_requester(self):
        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        # Act & Assert
        self.assertEqual_block(block1, db.get_by_public_key_and_sequence_number(
            block1.public_key_requester, block1.sequence_number_requester))

    def test_get_by_public_key_and_sequence_number_responder(self):
        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        
        # Act & Assert
        self.assertEqual_block(block1, db.get_by_public_key_and_sequence_number(
            block1.public_key_responder, block1.sequence_number_responder))

    def test_get_total(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder + 1
        block2.total_up_requester = block1.total_up_responder + block2.up
        block2.total_down_requester = block1.total_down_responder + block2.down
        db.add_block(block2)
        # Act
        (result_up, result_down) = db.get_total(block2.public_key_requester)
        # Assert
        self.assertEqual(block2.total_up_requester, result_up)
        self.assertEqual(block2.total_down_requester, result_down)

    def test_get_total_not_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        # Act
        (result_up, result_down) = db.get_total(block2.public_key_requester)
        # Assert
        self.assertEqual(-1, result_up)
        self.assertEqual(-1, result_down)

    def test_save_large_upload_download_block(self):
        """
        Test if the block can save very large numbers.
        """  # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        block1.total_up_requester = long(pow(2, 62))
        block1.total_down_requester = long(pow(2, 62))
        block1.total_up_responder = long(pow(2, 61))
        block1.total_down_responder = pow(2, 60)
        # Act
        db.add_block(block1)
        # Assert
        result = db.get_by_hash(block1.hash_requester)
        self.assertEqual_block(block1, result)

    def test_get_insert_time(self):
        # Arrange
        # Upon adding the block to the database, the timestamp will get added.
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        block1 = TestBlock()
        db.add_block(block1)

        # Act
        # Retrieving the block from the database will result in a block with a
        # timestamp
        result = db.get_by_hash(block1.hash_requester)

        insert_time = datetime.datetime.strptime(result.insert_time,
                                                 "%Y-%m-%d %H:%M:%S")

        # We store UTC timestamp
        time_difference = datetime.datetime.utcnow() - insert_time


        # Assert
        self.assertEquals(time_difference.days, 0)
        self.assertLess(time_difference.seconds, 10,
                        "Difference in stored and retrieved time is too large.")

    def test_validate_existing(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('valid', []))
        self.assertEqual(b, ('valid', []))

    def test_validate(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('valid', []))
        self.assertEqual(b, ('valid', []))

    def test_validate_no_info(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (_, _, _, block4) = self.setup_validate(db, dispersy)
        db.add_block(block4)
        # Act
        (a, b) = self.validate_block(db, block4)
        # Assert
        self.assertEqual(a, ('no-info', ['No blocks are know for this member before or after the queried sequence number']))
        self.assertEqual(b, ('no-info', ['No blocks are know for this member before or after the queried sequence number']))

    def test_validate_partial_prev(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (_, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('partial-prev', []))
        self.assertEqual(b, ('partial-prev', []))

    def test_validate_partial_next(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (_, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        (a, b) = self.validate_block(db, block3)
        # Assert
        self.assertEqual(a, ('partial-next', []))
        self.assertEqual(b, ('partial-next', []))

    def test_validate_partial(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, _, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        (a, b) = self.validate_block(db, block3)
        # Assert
        self.assertEqual(a, ('partial', []))
        self.assertEqual(b, ('partial', []))

    def test_invalid_existing_up(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        block2.up += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Up does not match known block', 'Total up is lower than expected compared to the preceding block']))
        self.assertEqual(b, ('invalid', ['Up does not match known block', 'Total down is lower than expected compared to the preceding block']))

    def test_invalid_existing_down(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        block2.down += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Down does not match known block', 'Total down is lower than expected compared to the preceding block']))
        self.assertEqual(b, ('invalid', ['Down does not match known block', 'Total up is lower than expected compared to the preceding block']))

    def test_invalid_existing_tup(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        block2.total_up_requester += 10
        block2.total_up_responder += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total up does not match known block', 'Total up is higher than expected compared to the next block']))
        self.assertEqual(b, ('invalid', ['Total up does not match known block', 'Total up is higher than expected compared to the next block']))

    def test_invalid_existing_tdown(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        block2.total_down_requester += 10
        block2.total_down_responder += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total down does not match known block', 'Total down is higher than expected compared to the next block']))
        self.assertEqual(b, ('invalid', ['Total down does not match known block', 'Total down is higher than expected compared to the next block']))

    def test_invalid_existing_hash(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block2)
        db.add_block(block3)
        # Act
        block2.previous_hash_requester = sha1(str(random.randint(0, 100000))).digest()
        block2.previous_hash_responder = sha1(str(random.randint(0, 100000))).digest()
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Previous hash does not match known block', 'Previous hash is not equal to the id of the previous block']))
        self.assertEqual(b, ('invalid', ['Previous hash does not match known block', 'Previous hash is not equal to the id of the previous block']))

    def test_invalid_seq_not_genesis(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, _, _, _) = self.setup_validate(db, dispersy)
        # Act
        block1.previous_hash_requester = sha1(str(random.randint(0, 100000))).digest()
        block1.previous_hash_responder = sha1(str(random.randint(0, 100000))).digest()
        (a, b) = self.validate_block(db, block1)
        # Assert
        self.assertEqual(a, ('invalid', ['Sequence number implies previous hash should be Genesis ID']))
        self.assertEqual(b, ('invalid', ['Sequence number implies previous hash should be Genesis ID']))

    def test_invalid_seq_genesis(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.previous_hash_requester = GENESIS_ID
        block2.previous_hash_responder = GENESIS_ID
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Sequence number implies previous hash should not be Genesis ID', 'Genesis block invalid total_up and/or up', 'Genesis block invalid total_down and/or down', 'Previous hash is not equal to the id of the previous block']))
        self.assertEqual(b, ('invalid', ['Sequence number implies previous hash should not be Genesis ID', 'Genesis block invalid total_up and/or up', 'Genesis block invalid total_down and/or down', 'Previous hash is not equal to the id of the previous block']))

    def test_invalid_genesis(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, _, _, _) = self.setup_validate(db, dispersy)
        # Act
        block1.up += 10
        block1.down += 10
        (a, b) = self.validate_block(db, block1)
        # Assert
        self.assertEqual(a, ('invalid', ['Genesis block invalid total_up and/or up', 'Genesis block invalid total_down and/or down']))
        self.assertEqual(b, ('invalid', ['Genesis block invalid total_up and/or up', 'Genesis block invalid total_down and/or down']))

    def test_invalid_up(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.up += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total up is lower than expected compared to the preceding block']))
        self.assertEqual(b, ('invalid', ['Total down is lower than expected compared to the preceding block']))

    def test_invalid_down(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.down += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total down is lower than expected compared to the preceding block']))
        self.assertEqual(b, ('invalid', ['Total up is lower than expected compared to the preceding block']))

    def test_invalid_tup(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.total_up_requester += 10
        block2.total_up_responder += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total up is higher than expected compared to the next block']))
        self.assertEqual(b, ('invalid', ['Total up is higher than expected compared to the next block']))

    def test_invalid_tdown(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.total_down_requester += 10
        block2.total_down_responder += 10
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Total down is higher than expected compared to the next block']))
        self.assertEqual(b, ('invalid', ['Total down is higher than expected compared to the next block']))

    def test_invalid_hash(self):
        # Arrange
        dispersy = self.MockDispersy()
        db = MultiChainDB(dispersy, self.getStateDir())
        (block1, block2, block3, _) = self.setup_validate(db, dispersy)
        db.add_block(block1)
        db.add_block(block3)
        # Act
        block2.previous_hash_requester = sha1(str(random.randint(0, 100000))).digest()
        block2.previous_hash_responder = sha1(str(random.randint(0, 100000))).digest()
        (a, b) = self.validate_block(db, block2)
        # Assert
        self.assertEqual(a, ('invalid', ['Previous hash is not equal to the id of the previous block']))
        self.assertEqual(b, ('invalid', ['Previous hash is not equal to the id of the previous block']))

if __name__ == '__main__':
    unittest.main()
