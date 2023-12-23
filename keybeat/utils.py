class KeybeatError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

KEYBEAT_ARMOURED_HEADER = "-----BEGIN KEYBEAT PROOF OF LIFE-----\n"
KEYBEAT_ARMOURED_FOOTER = "\n-----END KEYBEAT PROOF OF LIFE-----"
